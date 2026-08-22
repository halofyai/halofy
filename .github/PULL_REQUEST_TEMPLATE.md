## What this changes

<!-- One paragraph. What is different after this merges, and why. Link the issue or
     discussion it comes from. If there is no issue, say why the change is obvious
     enough not to need one. -->

Closes #

## How it was verified

<!-- Paste the REAL output of the commands you ran. Not a summary of it, not
     "tests pass". A quiet or timed-out run is unverified until it exits with
     counts. Redact keys and hostnames. -->

```
$ cd kernel && npm run typecheck

$ cd kernel && npm test

```

## Verification scope

Verification is proportional to blast radius. Tick the row that matches this change
and delete the others.

- [ ] **Docs only, outside `kernel/`** — re-read the structure, `git diff --check`. No test run.
- [ ] **Isolated console renderer, copy or CSS** — `node --check` on the changed files, the directly affected `test/*console-*.test.ts`, and I looked at the real browser state.
- [ ] **Isolated kernel behaviour** — the focused vitest file(s), `npm run typecheck`, plus `npm run build` if emitted code changed.
- [ ] **Auth, ACL, tenancy, policy, audit, write path, MCP, encryption, migrations, or anything cross-cutting** — focused adversarial regressions, the full `npm test`, typecheck and build, plus `npm run test:pg` where SQL behaviour is involved.

## Non-negotiables

These are not style preferences. A PR that cannot tick the applicable boxes will be
sent back.

- [ ] **No test was weakened to make this pass.** No assertion loosened, no case skipped, no expectation rewritten to match new behaviour. If a test genuinely contradicted a contract, I say so below and name which one I changed — the contract or the code.
- [ ] **No fabricated results.** Every command output pasted above is from a real run on this branch.
- [ ] **New behaviour has a regression test** that fails without this change.
- [ ] **The CLA is signed** (see CLA.md), or this is my first PR and I will sign when the bot asks.

## Boundaries touched

Tick anything this PR touches, and answer the follow-up. Leave unticked what does not apply.

- [ ] **ACL or namespace matching.** A caller in namespace `N` sees rows whose namespace is `N` or a `/`-split prefix ancestor of `N`. Siblings and descendants stay invisible. Enforcement lives in the query/repository layer, never in callers. Any SQL `LIKE` over a namespace uses `ESCAPE` — `_`, `%` and backslash in namespaces have caused leaks twice. I added a cross-namespace regression test.
- [ ] **Audit.** Every syscall writes an `audit_log` row, including denied, miss, brownout and error outcomes. Any new denial or failure path added here writes its row, and a test asserts the row exists. `audit_log` remains append-only.
- [ ] **Migrations.** Appended with a new number; no deployed migration was rewritten or renumbered. Every `CREATE TABLE` also runs `ENABLE ROW LEVEL SECURITY`. I ran `npm run test:pg`.
- [ ] **Supersedence and immutability.** A conflicting fact closes the prior fact's validity and links to it. Nothing is overwritten and nothing is deleted (D7).
- [ ] **Identity.** Namespace, actor, role, team and source scope are resolved server-side from the API key. No code path added here reads any of them from a request body (D9).
- [ ] **Retrieval boundary.** No competitive retriever was built in the kernel (D1). The allocator still returns ranked blocks and assembles no prompts (D2). If a driver changed, `npx tsx src/cli.ts conformance <driver>` reports 6/6 and the output is pasted above.
- [ ] **Ingestion.** Importers and connectors feed the write path and never the store directly, so imported data gets the same extraction, verification, provenance, policy and audit as agent conversation (D10).
- [ ] **Credentials and tokens.** Write-only to clients, encrypted at rest. Raw-body signature verification, replay claims and epoch fencing are preserved.
- [ ] **Failure behaviour.** New failure paths brown out and log rather than hard-failing — but no missing security evidence is converted into success.
- [ ] **License boundary.** Nothing moved from an AGPL directory into an Apache-2.0 subtree (`kernel/src/driver/`, `kernel/src/mcp/`, `kernel/integrations/` — each carries its own `LICENSE`). That direction silently relicenses AGPL code and is not permitted. See LICENSING.md.

## Documentation

- [ ] Docs updated in the same PR — check one and delete the other.
- [ ] No documentation change is needed, because: <!-- reason -->

## Anything a reviewer should know

<!-- Trade-offs you made, alternatives you rejected, parts you are unsure about,
     pre-existing failures you observed and deliberately did not repair. Say so
     here rather than leaving them to be discovered. -->

---

I have seen this code, I have run this code, and I take responsibility for this code.
