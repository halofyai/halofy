# Open build vs. managed service

A capability-by-capability comparison of what you get by running this repository
yourself, and what Halofy sells on top of it.

The boundary itself — what is open, why, and what happens if we ever move it —
is a binding document: [OPEN-SOURCE-SCOPE.md](../../OPEN-SOURCE-SCOPE.md). This
page is the practical version of that promise. Where the two disagree, the scope
document wins.

Two things worth stating before the table, because they are the questions people
actually have:

- **The open build is not a trial.** There is no licence key, no edition flag, no
  seat cap, no document cap, and no expiry. The kernel does not check whether it
  is the community build, because there is no such concept in the code.
- **The open build does not phone home.** No telemetry, no usage beacon, no
  remote feature flags. If you self-host, the kernel never contacts Halofy.

---

## Access and governance

Everything in this section is fully open. This is the product's core boundary:
who an agent is, what organizational context it may use, how that context may
change, and how every decision is recorded.

| Capability | Open build | Managed |
|---|---|---|
| `mem_write` custody pipeline — extract, verify, resolve entities, dedupe, supersede, provenance, audit | Full | Same code |
| Supersedence chains and bi-temporal validity (D7) | Full | Same code |
| Hierarchical ACL, enforced in the query layer | Full | Same code |
| Server-side identity resolution from an API key (D9) | Full | Same code |
| Append-only audit on every outcome, including denials (D4) | Full | Same code |
| Signed `DeletionCertificate` erasure, offline-verifiable | Full | Same code |
| Multi-tenant isolation and its adversarial test suite | Full | Same code |
| Policy documents, directives, acknowledgement ledger | Full | Same code |
| Export, manifest, and schema portability | Full | Same code |
| L2 (Postgres/pgvector) and L3 (encrypted, Git-versioned concepts) tiers | Full | Same code |
| Context faults, allocator budget packing, working sets | Full | Same code |
| Retrieval driver cartridges + the 6-check conformance kit | Full | Same code |
| Console: memory, sources, teams, policy, conflicts, audit, export | Full | Same, plus the commercial screens below |
| The hermetic test suite that proves all of the above | Full | Same code |

## Operations Halofy runs for you

These are the paid product. Each one is a service with vendor contracts, an
on-call rotation, or an upstream catalogue to keep working — not a feature
withheld from the kernel.

| Capability | Open build | Managed |
|---|---|---|
| Model routing across providers | Not included | Included |
| Spend attribution per team, agent, and model | Not included | Included |
| Gateway observability and cost reporting | Not included | Included |
| Billing, credit ledger, invoices | Not included — and no disabled quota system either | Included |
| Managed Slack / Discord / WhatsApp / Google Chat apps | Not included. Build your own against the open write path (D10) | Included, operated |
| Hosted connector catalogue (OAuth apps, credential custody, upstream API maintenance) | Not included | Included |
| Connector **framework**, plus filesystem, Postgres, CSV and Obsidian connectors | Full | Same code |
| Federated live query across organizations | Not included | Included |
| Tuned extraction prompt pack | Baseline prompts ship; the tuned set does not | Included |
| Managed Postgres, backups, upgrades, uptime | You run it | Included |
| Support with a response commitment | Community only | Contractual |

## Licensing

| | Open build | Managed |
|---|---|---|
| Kernel and console | AGPL-3.0-or-later | Commercial licence available |
| Driver kit, MCP server, integrations | Apache-2.0 | Apache-2.0 |
| Obligation if you modify and offer it over a network | Publish your modifications | Removed by the commercial licence |

See [LICENSING.md](../../LICENSING.md). If AGPL network copyleft does not fit
your deployment, the commercial licence exists specifically for that:
<licensing@halofy.ai>.

---

## Choosing

**Run the open build if** you want to operate the access and governance layer
inside your own organization. Nothing about it is crippled. It runs a full
end-to-end story with no API key, no database server, no network, and no model
download — see [getting-started.md](../getting-started.md).

**Buy the managed service if** you want the AI gateway (routing, spend
attribution, observability), the hosted connector catalogue, managed channel
apps, cross-organization federation, or somebody accountable for uptime.

**Buy a commercial licence, without the managed service, if** you need the code
under terms other than AGPL-3.0.

You are not locked into that choice in either direction. The schema is plain
Postgres with pgvector, the export path is open, and there is no deliberately
lossy export designed to make leaving harder — that is a stated commitment, not
a courtesy (scope document, section 2.11).

## What this page is not

It is not a promise of feature parity. The managed product will have
capabilities the open build does not; that is how the open work is funded. What
it will not have is capabilities *taken from* the open build. That is the
ratchet described in scope section 5: capabilities move from commercial to open,
never the other way.
