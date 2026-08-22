# Open Source Scope

**A binding statement of what stays open.**

Version 1.0 — effective 2026-08-22
Supersedes: nothing. Superseded by: nothing.
Questions or challenges: open a GitHub Discussion, or <licensing@halofy.ai>.

---

## Why this document exists

Halofy is a single-vendor open source project. Halofy writes most of the code,
owns the trademarks, and sells a commercial product built on the same
foundation. That arrangement funds the open work. It also creates an obvious
risk, and you are right to be suspicious of it: the vendor who gives you a
capability can take it back in the next minor release.

That risk is structural, not theoretical. A vendor can narrow an open edition,
move a capability behind a hosted service, or introduce limits after users have
built around the original behaviour. A licence alone does not promise that
future versions will preserve today's useful boundary.

Giving AI agents access to an organization's shared context is a decision with
a long tail. You are choosing where facts about your company will live for
years, who may use them, how changes are governed, and what audit trail proves
those decisions. You cannot make that choice responsibly against a project
that might shrink under you. So this document states, at a level that survives
refactoring, what will not shrink.

Everything below is a commitment about **the project**, made by Halofy, in
public, versioned, and diffable. Where it conflicts with marketing copy, a
support conversation, or a sales deck, this document wins.

---

## 1. How the guarantee is written

The guarantee is stated as **capabilities**, not as file paths.

A promise pinned to `kernel/src/audit/index.ts` is broken by a routine rename. A
promise that *"every syscall outcome, including denials, misses, brownouts and
errors, is recorded in an append-only audit trail that ships in the open
repository"* survives any refactor that keeps the behaviour. It can only be
broken deliberately.

So the unit of commitment is: **a capability, exercised through a public surface
(syscall, HTTP route, console screen, or CLI command), with a test in the open
test suite that proves it.** Files move. Modules merge. Tests get rewritten. The
capability stays, and the open test suite keeps proving it.

Throughout this document:

- **Open** means present in the public repository, under AGPL-3.0-or-later
  (or Apache-2.0 for the permissive subtrees named in `NOTICE`), with source you
  can read, modify, build, run and redistribute under those terms.
- **Self-hosted** means running the open build on infrastructure you control,
  with no dependency on any Halofy-operated service.
- **Commercial** means sold by Halofy: the hosted control plane, and the closed
  subsystems named in section 4.

---

## 2. Permanently open capabilities

Each of the following is open today and will remain open. Section 3 states what
"will remain" is worth and what happens if we ever cannot honour it.

### 2.1 The memory syscalls

The memory syscalls — `mem_write`, `mem_write_status`, `mem_read`,
`mem_search`, `mem_assemble`, `mem_fault`, `mem_pin`, `mem_unpin`, `mem_stats`,
`mem_forget`, `mem_policy`, `mem_policy_ack`, `mem_share` and `mem_manifest` —
stay open, exposed over MCP, over the HTTP API, and through the kernel library.
None of them is degraded in the open build: there is no "community edition"
variant of a syscall that returns less than the commercial one returns for the
same input.

The one call not in that list is the redemption step for the federated
live-query lane, because cross-organization federation is itself commercial
(section 4). Nothing in the local memory path depends on it.

### 2.2 The write path, including supersedence

Halofy's claim is custody of memory: what gets written, where it is placed, how
it moves, how it is governed. That claim is only auditable if the write path is
readable. So the whole path stays open — extraction, verification, provenance
capture, placement, and the supersedence machinery that makes a conflicting fact
close the prior fact's validity window and link to it rather than overwrite it
(D7: stable ULIDs, never overwrite, never delete).

Corollary: **connectors and importers feed the write path, never the store
directly** (D10). Any ingestion route Halofy ships — open or commercial — passes
through the same open extraction, verification, provenance, policy and audit
code. A commercial connector cannot write memory by a private path with weaker
governance, because no such path exists in the open kernel and none will be
added.

### 2.3 ACL and tenancy enforcement

The access rule — a caller in namespace `N` sees rows whose namespace is `N` or a
`/`-split prefix ancestor of `N`; siblings and descendants are invisible — is
enforced in the query and repository layer, in open code, and its adversarial
regression tests are in the open test suite. Multi-tenant isolation is not a
paid feature. Row-level security on new tables is a contribution rule, not an
upsell.

Also open, and staying open: server-side identity resolution from an API key
(D9). No caller-asserted namespace, actor, role, team or source scope is ever
trusted. That is the single most security-critical decision in the system and it
is not something you should have to take on faith.

### 2.4 The append-only audit trail

Every syscall writes an audit row — including denied, miss, brownout and error
outcomes (D4). The audit log is append-only by construction. The writer, the
schema, the retention behaviour and the read surfaces stay open.

This one is close to non-negotiable for an independent reason: you cannot
credibly sell auditable memory while the audit implementation is a secret. A
customer's compliance function has to be able to read the code that produces the
evidence. Closing this would destroy the product's central claim, so it is both
a promise and a fact about our incentives.

### 2.5 Erasure and signed erasure certificates

`mem_forget` — the one governed exception to "never delete" (D3) — stays open,
including cascade resolution across tiers and caches, the erasure fence that
keeps deleted content from being resurrected by a warm store or cold tier, and
the ed25519-signed deletion certificate with its verification function. Being
able to *prove* a deletion happened is the part that matters under GDPR-style
obligations, and proof you cannot inspect is not proof.

### 2.6 The context allocator

The allocator that ranks blocks under a token budget stays open, including
budget discipline and pinning. It returns ranked blocks; it never assembles
prompts (D2). Prompt assembly belongs to your agent framework, and that boundary
is itself part of what is open: we do not intend to grow a closed prompt
assembler that the open allocator quietly defers to.

### 2.7 The retrieval driver interface and the conformance kit

Retrieval is delegated, permanently (D1). The driver interface
(`halomem-driver/v1`), the reference cartridges, and the conformance kit that
mechanically enforces the read-only boundary all stay open — and the driver
interface stays **Apache-2.0**, specifically so you can write a cartridge, keep
it under whatever licence you like, and mount it without the AGPL reaching your
code.

`npx tsx src/cli.ts conformance <driver>` runs six checks — `finds-planted-fact`,
`respects-scoped-view`, `latency-envelope`, `budget-discipline`, `read-only`,
`deterministic-k` — against any cartridge, including one we did not write. That
command stays open, and third-party cartridges will not be second-class: no
capability will be gated on running a Halofy-authored driver.

### 2.8 The console

The control room — setup, home, the memory map, scoped memory, sources,
knowledge operations, policies, conflicts, audit, teams, alerts, export, agent
connections, connected apps, skills and settings — stays open. It is the
primary human surface over the kernel, and a governance product whose only usable
interface is a paid SaaS console is not a governance product you control.

Screens that exist only to operate a commercial subsystem (model routing, spend,
billing, managed channels) are not in the open build, because the subsystems they
drive are not. That is section 4, and it is a different thing from removing an
open screen.

### 2.9 The test suite

The tests stay open, and they stay **hermetic**: in-memory PGlite with pgvector,
a deterministic stub LLM, a hash embedder, zero network. `npm test` needs no API
key, no database and no credentials.

This matters more than test suites usually do. The tests are how you verify the
promises in this document without trusting us — the ACL adversarial cases, the
supersedence regressions, the audit-completeness assertions, the erasure and
certificate-verification tests. Shipping the code but withholding the tests
would make the guarantee unfalsifiable. So the suite ships, and every capability
in section 2 keeps proving itself there.

### 2.10 Self-hosting, without ceilings

The self-hosted build is complete and unmetered:

- **No licence key.** No edition flag, no activation, no entitlement check, no
  code path that behaves differently because it believes it is the community
  build.
- **No caps imposed by us.** No seat limit, no namespace limit, no document
  limit, no memory count limit, no retention ceiling. Your limits are your
  Postgres and your hardware. The standalone `QuotaPort` defaults to
  `UNMETERED`; the hosted billing and trial-quota implementations are not in
  this repository. A per-key rate limit defaults to 60 requests/minute and an
  optional model-budget brownout can be set per namespace. Both are
  operator-owned policy controls, not packaging quotas, and both are
  documented in `docs/self-hosting.md`.
- **No phone-home.** No telemetry, no usage beacon, no anonymous statistics, no
  in-product upsell fetched from a remote flag service. The build does not talk
  to Halofy, ever, and you can grep for that.
- **No credential requirement.** The kernel runs a full end-to-end story with no
  API key, no external database, no network access and no model download, using
  the deterministic stub LLM and hash embedder. `npm run demo` is the proof.
  Offline operation is a permanent property, not a starter mode.

The container build, the compose file, the Kubernetes manifests, the migration
runner and the backup/restore scripts stay open.

### 2.11 Your data stays yours

Schema migrations, the export surface and the manifest/portability path stay
open. The database is plain Postgres with pgvector; the schema is readable; the
data is yours in a form that does not require our software to interpret. There
will never be an export that is deliberately lossy to make leaving harder.

### 2.12 Governance of the project itself

`GOVERNANCE.md`, `CONTRIBUTING.md`, `SECURITY.md`, the architecture decision
records and this document stay in the repository, in the open, with their
history intact.

---

## 3. The no-removal promise

For each capability in section 2, Halofy commits that:

1. **It will not be moved behind the commercial product.** Not by deletion, not
   by relocation into a closed subsystem, not by leaving a stub in the open tree
   that requires a Halofy-hosted service to function.

2. **It will not be degraded to create an upgrade path.** No artificial limits,
   no deliberately worse defaults, no "the open build only keeps ninety days of
   audit", no throttle whose only purpose is to make the paid version feel
   better.

3. **It will not be conditioned on payment, registration, telemetry or an
   account.** The open build will not require an activation call, a login, an
   entitlement token, or opt-out telemetry.

4. **Its tests stay open too.** A capability whose proof is withdrawn is a
   capability half-withdrawn.

5. **A superseded capability is replaced in the open, not removed to the
   commercial side.** Software changes. If the way pinning or supersedence works
   is redesigned, the redesigned capability lands open. What is forbidden is the
   capability leaving the open build.

### 3.1 If we ever cannot honour this

The honest part. Promises that pretend no future can break them are worth less
than promises that say what happens if one does.

Halofy holds the copyright and the trademarks. As a matter of law, nothing stops
a future Halofy from relicensing new versions or shrinking the open build. Prior
releases stay free forever — an AGPL grant already made cannot be revoked, and
every published version remains forkable under the licence it shipped with — but
that is a floor, not a guarantee about the future.

So here is the commitment that covers the case this document exists for:

> **If Halofy ever removes a capability listed in section 2 from the open build,
> or relicenses it under terms that are not an OSI-approved open source licence,
> we will change the project's name and identity rather than carry the open
> project's name onto the reduced thing.**
>
> Concretely: the reduced product ships under a different name, we hand the
> repository name to a community continuation, and we grant that continuation
> the trademark licence it needs to carry the name forward. `TRADEMARK.md` does
> not make that grant in advance — today a fork must rename (section 3 of that
> document) — and this is the commitment to make it if we are the ones who
> broke the promise. The users who chose Halofy because of this document keep
> the project they chose, including its name.

That clause is the point. Silent retraction is what damages people; it strands
work that was already built. A rename is loud, unmistakable, and leaves the
community holding a project that is still identifiably the thing they adopted.
We do not intend to use this clause. It exists so that using it would cost us
more than keeping the promise.

### 3.2 What this promise does not say

Stated plainly so nobody has to infer it:

- **It is not a support commitment.** The open build is community-supported. See
  `SUPPORT.md`.
- **It is not an API stability promise.** Interfaces evolve, and breaking
  changes are called out in the release notes. Capability guarantees survive
  breaking changes; individual function signatures do not.
- **It is not a promise to open everything.** Section 4 names what is
  commercial and is expected to stay commercial.
- **It is not a promise about the hosted service.** Halofy's managed offering
  has its own terms, prices and lifecycle, and may be discontinued.
- **It is not a promise of feature parity.** The commercial product will have
  capabilities the open build does not. That is the deal. What it will not have
  is capabilities *taken from* the open build.

---

## 4. What is commercial, and why

Argued rather than apologised for. If the reasoning is wrong, argue with it in a
Discussion — but the split is deliberate, not arbitrary.

The line we drew: **the access and governance boundary is open; the operations
business around it is commercial.** Everything required to resolve identity,
enforce access, store, govern, audit, erase, and retrieve organizational context
on your own infrastructure is in the open build.
Everything that is fundamentally a *service Halofy runs on your behalf* — with
vendor contracts, an on-call rotation, an upstream API catalogue to keep working,
and a bill — is commercial.

**The AI gateway: model routing, spend attribution, observability.** Routing
inference across providers, attributing spend to teams and agents, and reporting
on it is a different product from an access and governance kernel. It requires
provider relationships, per-model rate cards that change monthly, and someone
paid to keep them accurate. Open-sourcing it would not make your governance
boundary more trustworthy; it would just hand a competitor a price book.

**Billing, credit ledgers and usage caps.** These exist to bill Halofy's
customers. They are useless to a self-hoster, so their implementations are not
in the open build. The kernel depends only on the public `QuotaPort`, whose
standalone implementation is `UNMETERED`. Operator-configured rate limits and
model-budget brownout remain open governance controls; they are not billing or
plan enforcement.

**Managed channels (Slack, Discord, WhatsApp, Google Chat).** These are
platform-app operations: a single verified app per platform, app-review
processes, token custody for other people's workspaces, webhook uptime, and
per-platform compliance obligations. What is sold is the operational burden, not
the code. The write path they feed is open (D10), so a self-hoster can build a
channel integration against the open kernel without asking us.

**The managed connector catalogue.** Dozens of hosted SaaS connectors with OAuth
apps we register, credentials we hold, and upstream API changes we chase. The
**connector framework** is open, and so are the connectors that need no vendor
relationship — filesystem, Postgres, CSV and Obsidian. You can write
your own connector against the open framework and it feeds the same open write
path. What is sold is the maintained catalogue.

**The tuned extraction prompt pack.** The LLM plumbing is open — the provider
clients for Anthropic, Azure OpenAI and any OpenAI-compatible endpoint, the
deterministic stub the demo and the test suite run on, the loose-JSON parser and
the factory — along with a baseline prompt set the open build uses when you point
it at a real model, so extraction works without us. What is closed is the
specific tuned prompt set behind our hosted extraction quality. Prompts are the
one asset in this system that copies in a single paste, carries no code and no
licence signal, and represents most of the tuning cost. Closing them keeps the
pipeline honest — you can read every line of code that decides what happens to an
extracted fact, and the prompts are a swappable input to that code rather than
part of it.

**Federation across organizations, and the hosted control plane.** Cross-org
capability and the service Halofy runs for customers who would rather not run
Postgres.

Underneath all of this: **our only source of funding for the open work is the
commercial product.** No donation model, no bounty program, no grant. If the
commercial product does not sell, the open kernel does not get maintained. We
would rather say that plainly than pretend the boundary is a matter of
philosophy.

---

## 5. How the boundary moves

**One direction only: commercial to open. Never open to commercial.**

Moving a capability from the commercial side into the open build is an ordinary
release note. Moving anything in section 2 the other way is the event described
in 3.1.

This is a ratchet by design. It means every decision to open something is
irreversible, so we make those decisions deliberately rather than as marketing —
and it means a capability's presence in the open build is information you can
rely on when you plan a deployment.

Two mechanical notes that follow from it:

- **Licence direction inside the repository is also one-way.** Code may move from
  an Apache-2.0 subtree into the AGPL kernel. It must never move the other way:
  refactoring an AGPL helper "up" into one of the Apache-2.0 subtrees named in
  `NOTICE` silently relicenses it. Halofy can relicense its own code; a
  contributor cannot relicense anyone else's. See `CONTRIBUTING.md`.
- **New capabilities are not covered by section 2 until they are listed there.**
  A feature shipping in the open build is open, and stays open for that release
  under its licence — but the permanent, rename-backed guarantee attaches only
  to capabilities enumerated in section 2 of a published version of this
  document. Section 2 grows through pull requests, and growing it is the
  ratchet turning.

---

## 6. Versioning this promise

This document is versioned, and its version is quotable.

- **Version 1.0** is the release above.
- **Minor version (1.x)** — clarifications, and additions to section 2. Anything
  that widens or sharpens the guarantee.
- **Major version (2.0)** — any change that narrows it. Under section 3.1, a
  narrowing that removes a section 2 capability from the open build also triggers
  the rename, so a major version of this document is never a quiet event.

Every change lands through a pull request against this file, so the diff is
public and permanent. Every change is recorded in `CHANGELOG.md`. Prior versions
remain in git history and remain the terms under which the releases they
accompanied were published — a later version does not retroactively narrow an
earlier promise. Each release of Halofy is governed by the version of this
document in that release's tag.

If you are making an adoption decision and want the guarantee in writing against
a specific version, cite it: *"OPEN-SOURCE-SCOPE.md v1.0, section 2.4."*

**To hold us to it:** open a GitHub issue titled `scope: <capability>` quoting
the version and section, or email <licensing@halofy.ai>. A claim that this
document has been violated is treated as a defect report against the project,
not as feedback — it gets a public answer in the issue, on the record.
