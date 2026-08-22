# Contributing to HaloMem

Thanks for being here. This document is how to get a change merged with the
least friction on both sides.

Two things worth knowing before you spend time:

- **Halofy signs contributions under a CLA.** It takes about thirty seconds, once.
  Section 9 explains what it is and why it exists, without hedging.
- **Some areas are maintained in-house** and outside pull requests are usually
  declined there. Section 2 names them, so nobody discovers this after writing
  the patch.

---

## 1. Where to start

| You want to | Go to |
|---|---|
| Ask how something works | GitHub Discussions — see `SUPPORT.md` |
| Report a reproducible bug | GitHub Issues, bug report form |
| Report a vulnerability | **Not** an issue. See `SECURITY.md` |
| Propose a feature | Discussions first, then an issue if it converges |
| Change architecture or a locked decision | An ADR. See `GOVERNANCE.md` |
| Fix a typo, a doc, a broken link | Just open the PR |

**Discuss before you build anything non-trivial.** A short issue describing the
problem, the approach and the blast radius saves you from writing a patch that
was going to be declined on design grounds. For anything under a hundred lines
that does not touch section 2 or section 5, skip straight to the PR.

---

## 2. What is maintained in-house

Pull requests touching these are usually declined, not because contributions are
unwelcome but because a mistake here is a security incident and the review cost
exceeds the patch:

- `kernel/src/auth/`, `kernel/src/iam/`, `kernel/src/tenancy/`,
  `kernel/src/access-projection/` — identity, sessions, ACL, isolation
- `kernel/src/db/migrations.ts` — the append-only schema history
- `kernel/src/audit/` — the audit trail
- `kernel/src/policy/` — policy evaluation and enforcement
- `kernel/src/security/`, credential and token encryption
- The write/retrieval boundary: `kernel/src/write/`, `kernel/src/conformance/`,
  and the driver contract itself — `kernel/src/driver/index.ts` and
  `kernel/src/driver/view.ts`. **New cartridge files** under `kernel/src/driver/`
  are explicitly welcome; only the contract and the `ScopedView` are held.

**Bug reports and failing regression tests in these areas are extremely welcome**
— a test that demonstrates an ACL leak or a missing audit row is the single most
valuable thing you can send us. Open an issue (or a security report, if it is
exploitable) with the reproduction. We will write the fix.

Everywhere else — retrieval cartridges, connectors against the open framework,
importers, console screens, CLI ergonomics, docs, tests, performance,
observability, self-hosting and deployment — is open for contribution.

---

## 3. Development setup

Node 22 or later. No API keys, no database, no network access required.

```bash
git clone <your-fork>
cd kernel
npm install

npm test          # full hermetic suite
npm run typecheck # tsc --noEmit — must be clean
npm run demo      # end-to-end story, exits 0
```

`npm test` runs through `scripts/run-hermetic-tests.mjs`, which clears any real
`DATABASE_URL` and data-dir environment out of the way and marks the lane
hermetic so the Postgres and perf files are excluded. Vitest then runs each test
file in its own forked process, so no PGlite instance, module state or
environment mutation leaks between files. The suite is hermetic: in-memory
PGlite with pgvector, a deterministic stub LLM, a hash embedder, zero network.
If a test you wrote needs a credential or an outbound request, it is in the
wrong lane.

Running the server and the console:

```bash
npm run serve         # HTTP API on :8787, console at /console/login
npm run serve:dev     # same, with reload
npm run mcp           # MCP stdio server

npm run env:init      # generate local-only secrets into kernel/.env
npm run migrate       # apply the numbered schema migrations
docker compose up --build   # Postgres/pgvector + the kernel image
```

The admin surface is the CLI:

```bash
npx tsx src/cli.ts keygen <namespace> <actor> <role>
npx tsx src/cli.ts conformance <driver>                 # 6/6 for a well-formed cartridge
npx tsx src/cli.ts scorecard <namespace>
npx tsx src/cli.ts forget <target> <value> [namespace]  # prints the signed certificate
npx tsx src/cli.ts warmstore rebuild <name> <namespace>
```

`npx tsx src/cli.ts` with no arguments prints the full command list. Schema
migrations are applied with `npm run migrate`, not through the CLI.

The first key uses the bootstrap path that is available while `api_keys` is
empty.

**Real models are optional.** `ANTHROPIC_API_KEY` activates real LLM extraction
and `OPENAI_API_KEY` activates real embeddings. Without them the kernel runs
PGlite + `HashEmbedder` + `StubLlm`. That is the intended development default and
the offline path is a supported, permanently open capability — not a fallback
that is allowed to rot. If your change makes the no-credentials path worse, it
will be sent back.

### Running one test

```bash
npx vitest run test/write-path.test.ts --maxWorkers=1
npx vitest run -t "supersede" --maxWorkers=1
```

Keep `--maxWorkers=1` for targeted runs: PGlite is single-process.

Other lanes, for when they apply:

```bash
npm run test:serial   # whole suite pinned to one worker
npm run test:pg       # Postgres lane, needs a real DATABASE_URL
npm run test:perf     # p95 latency gates, needs an uncontended machine
npm run build         # emit dist/
```

**A quiet run or a timed-out run is not a pass.** Only a run that exits with
printed counts is evidence.

---

## 4. Code conventions

- **Node 22, ESM.** Relative imports end in `.js`, even in TypeScript sources:
  `import { foo } from "./bar.js"`. This is not a typo; it is what the runtime
  resolves.
- **Strict TypeScript.** No `any` unless genuinely unavoidable, and say why in a
  comment when it is.
- **Shared types live in `src/types.ts`.** Import them from there, never from
  another module's internals. A type reaching across module boundaries by any
  other route is a design smell that the review will catch.
- **Database access goes through the shared `Db` handle.** Do not open your own
  connection, do not construct your own pool.
- **pgvector parameters bind as strings**, in the `'[0.1,0.2]'` form. Use the
  existing `toVectorLiteral` helper rather than formatting one by hand.
- **Boundary timestamps are ISO-8601.** Anything crossing an HTTP, MCP, CLI or
  storage boundary is a string in ISO-8601, not an epoch number and not a `Date`.
- **Escape every untrusted value in the console** with the shared console escape
  primitive. The console is string-rendered with no framework and no build step;
  escaping is manual and mandatory.
- **Match the file you are editing.** No reformatting passes, no import
  reordering, no style-only diffs mixed into a behaviour change.

---

## 5. Non-negotiables

These are not style preferences. A PR that violates one does not get merged in
that shape, however good the rest of it is.

1. **Never weaken a test to make it pass.** Not by loosening an assertion, not by
   deleting a case, not by adding a skip. If a test genuinely contradicts a
   contract, then either the contract or the code is wrong — fix the right one
   and say in the PR description which one you decided it was, and why.

2. **ACL is enforced in the query and repository layer, never in callers.** A
   namespace `N` sees rows whose namespace is `N` or a `/`-split prefix ancestor
   of `N`. Siblings and descendants are invisible. Admin subtree reads are
   explicit, narrow exceptions. If your change filters by namespace in a route
   handler, a service, or a console read model, it is in the wrong layer and the
   next caller will forget to do it.

3. **Never use SQL `LIKE` for a namespace prefix without `ESCAPE`.** Namespaces
   can contain `_`, `%` and backslashes, all of which are `LIKE` metacharacters.
   This has caused a cross-tenant leak here twice. Use the existing
   `escapeLikePattern` helper from `src/db/client.ts` and the established
   `... = $1 OR ... LIKE $2 ESCAPE '\'` shape rather than writing a new one.

4. **A new migration that `CREATE TABLE`s must `ENABLE ROW LEVEL SECURITY` on
   that table.** The owner and `service_role` bypass RLS, so the kernel is
   unaffected and PGlite does not care — but without it, a Supabase-hosted
   deployment re-exposes the table through the PostgREST anon key.

5. **Never rewrite a deployed migration.** `src/db/migrations.ts` is append-only
   and numbered. Fix a mistake with a new migration. Never renumber, never edit
   in place, never squash.

6. **Never overwrite, never delete.** A conflicting fact closes the prior fact's
   validity window and links to it. The one governed exception is `mem_forget`,
   which exists specifically so that erasure is explicit, cascading and
   certified.

7. **Every syscall writes an audit row** — including denied, miss, brownout and
   error outcomes. A new syscall path or a new early return that skips the audit
   write is a defect. Audit data is retrofit-impossible: a row not written today
   cannot be reconstructed tomorrow.

8. **Identity is resolved server-side from an API key.** Any code path that reads
   a namespace, actor, role, team or source scope from a request body is a bug,
   regardless of what it is used for.

9. **Brownout, never hard-fail.** If a backend, an LLM, or a budget cap fails,
   degrade and log it — verbatim writes, BM25-only search, pinned working set.
   But never convert missing security evidence into success. A policy check that
   could not run is a denial, not an allow.

10. **Drivers are read-only cartridges.** A module under `kernel/src/driver/` may
    import only `src/types.js`, `src/retrieval/` and `src/embed/`. Never storage,
    never the write path, never audit, never the barrel or the kernel facade.
    `npx tsx src/cli.ts conformance <driver>` enforces this mechanically.

11. **Never fabricate a result.** Run the command and paste the real output.
    "Should work" is not evidence, and a review that catches invented output ends
    the review.

---

## 6. The licence boundary inside the repository

The repository is AGPL-3.0-or-later, with a small number of Apache-2.0 subtrees:
`kernel/src/driver/`, `kernel/src/mcp/` and `kernel/integrations/`. `NOTICE` is
the authoritative list, and each such directory carries its own `LICENSE`.

**Code may move from an Apache-2.0 subtree into AGPL code. It must never move the
other way.** Refactoring a helper "up" out of `kernel/src/retrieval/` into
`kernel/src/driver/` silently relicenses AGPL code as Apache-2.0. Halofy can do
that with its own code; you cannot do it with anyone else's. If you need a helper
in a permissive subtree, write it there or say so in the PR so a maintainer can
make the relicensing decision explicitly.

Related: **no GPL-2.0-only dependency may ever be added**, since Apache-2.0 is
incompatible with GPLv2-only. New dependencies of any kind need a note in the PR
saying what they are for and under what licence.

---

## 7. Verification is proportional

Match the verification to the blast radius. Do not run the whole matrix for a
typo; do not skip it for an ACL change.

| Change | Run |
|---|---|
| Docs outside `kernel/` | Re-read it. `git diff --check`. No test run. |
| Isolated console renderer, copy, CSS | Syntax check, the directly affected `test/*console-*.test.ts`, and look at it in a real browser |
| Isolated kernel behaviour | The focused vitest file(s), `npm run typecheck`, `npm run build` if emitted code changed |
| Auth, ACL, tenancy, policy, audit, write path, MCP, OAuth, encryption, migrations, anything cross-cutting | Focused adversarial regressions, full `npm test`, `typecheck`, `build`, plus `npm run test:pg` when SQL behaviour is involved |

**Every behaviour change needs a test.** A bug fix needs a regression test that
fails before your change and passes after it — say so in the PR, and paste both
runs if the failure is subtle.

If you hit failures that were already broken before your change, note them in the
PR and leave them alone. Do not repair unrelated breakage in the same pull
request; open a separate issue.

---

## 8. Pull requests

- **Branch from `master`.** One logical change per PR. If you find a second bug
  while fixing the first, that is a second PR.
- **Fill in the template.** It asks for what changed, why, and pasted output from
  the commands you actually ran. Real terminal output, not a description of it.
- **Write the description for a reviewer who was not in the issue thread.** What
  was broken, what you changed, what you decided not to change and why.
- **Keep the diff reviewable.** If it exceeds a few hundred lines, split it, or
  say in the description how to read it.
- **Commit messages:** `area: imperative summary` — `write: close validity window
  on superseding fact`, `console: escape source labels in S6`. Body explains why.
- **Draft PRs are welcome** for early feedback. Mark them draft rather than
  apologising in the description.

CI runs typecheck, build, the hermetic suite, the no-credentials demo, driver
conformance and a dependency audit; a secret scan runs in its own workflow.
Every required check must be green, and the CLA must be signed, before a pull
request can merge.

Reviews are direct about defects and vague about nothing. If a reviewer asks for
a change you disagree with, say so with the reasoning — that conversation is the
review working, not a problem with it.

### AI-assisted contributions

Fine, and common here. Three conditions: you have read and understood every line
you are submitting, you have actually run it and can paste the output, and you
take responsibility for it as your own work. Disclose agent involvement in the PR
description. Unreviewed generated code — a patch whose author cannot explain what
it does — is closed without a line-by-line review.

---

## 9. The CLA

You will be asked to sign a Contributor License Agreement on your first pull
request. A bot comments with the link and the exact sentence to post. Once, not
per PR.

**Why it exists, plainly: so the project can be dual-licensed.** HaloMem is
AGPL-3.0-or-later, and Halofy sells a commercial licence to organizations whose
deployment cannot accept the AGPL's network-copyleft obligation. That commercial
licence is what funds the open work. Halofy can only offer those terms for code
it has the right to sublicense, and it can only have that right if every
contributor granted it in writing. The CLA is that grant. It also covers the
Apache-2.0 subtrees, which are under a different licence again.

**You keep your copyright.** The CLA is a licence, not an assignment. Your
contribution remains yours; you can use, publish and relicense it anywhere else
under any terms you like. Nothing about it is exclusive.

The full text is in `CLA.md` — in the repository, so it is diffable and versioned
like everything else. It is derived from the Apache Software Foundation's ICLA.
If your employer owns your work product, you likely need the Corporate CLA as
well; email <licensing@halofy.ai>.

What the CLA does *not* do: it does not let Halofy retract what is already open.
That commitment is `OPEN-SOURCE-SCOPE.md`, and it is worth reading before you
contribute — it is the promise you are contributing into.

---

## 10. Code of conduct

`CODE_OF_CONDUCT.md` applies to every space in this project. Report problems to
<conduct@halofy.ai>.
