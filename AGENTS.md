# AGENTS.md

Guidance for AI coding agents working in this repository. Full detail lives in
[CONTRIBUTING.md](CONTRIBUTING.md) (workflow, non-negotiables) and
[kernel/README.md](kernel/README.md) (scripts, layout, env vars).

## Layout and where commands run

- All code lives in **`kernel/`** — one npm package (`halomem-kernel`). Run every
  command from `kernel/`, not the repo root.
- `kernel/integrations/halomem-sync/` is its own npm package (Obsidian plugin).
- Root contains docs only: `docs/architecture.md` (conceptual model +
  per-directory map), `docs/security/threat-model.md`.

## Commands

```bash
cd kernel
npm ci
npm test            # hermetic suite: in-memory PGlite+pgvector, StubLlm, HashEmbedder, zero network
npm run typecheck   # tsc --noEmit — must be clean
npm run build       # emit dist/
npm run demo        # e2e story; exits 0 with NO credentials configured — that's the intended default
```

- Single file/test: `npx vitest run test/write-path.test.ts --maxWorkers=1`
  or `npx vitest run -t "supersede" --maxWorkers=1`. Keep `--maxWorkers=1` for
  targeted runs — PGlite is single-process.
- `npm run test:pg` needs a real `DATABASE_URL`. `npm run test:perf` needs an
  uncontended machine. Neither runs under plain `npm test`.
- Migrations apply via `npm run migrate` — not through the CLI.
- CLI: `npx tsx src/cli.ts` (bare prints all commands). Key ones: `keygen`,
  `conformance <driver>` (6-check driver kit), `scorecard`.
- A quiet or timed-out test run is not a pass — only an exiting run with printed
  counts counts as evidence.

## CI lanes (.github/workflows/ci.yml)

Typecheck+build · hermetic suite sharded 4× · demo with offline-path assertions
(`booted: embedder=hash(dim=256) llm=stub`) · driver conformance (`baseline`,
`graph`) · `npm audit --omit=dev --audit-level=high` · Obsidian plugin build
reproducibility (`git diff --exit-code -- main.js`). Node 22.x only. Console
`.js` files are syntax-checked with `node --check`.

## Non-negotiables (violations block merge)

1. **ACL enforcement lives in the query/repository layer** (`src/index/`), never
   in route handlers, services, or console read models. Namespace `N` sees rows
   whose namespace is `N` or a `/`-split prefix ancestor of `N`.
2. **Never use SQL `LIKE` for a namespace prefix without `ESCAPE`.** Namespaces
   contain `_`, `%`, `\`. Use `escapeLikePattern` from `src/db/client.ts` and the
   established `$1 OR LIKE $2 ESCAPE '\'` shape. This caused cross-tenant leaks
   twice already.
3. **Migrations are append-only** (`src/db/migrations.ts`): never rewrite,
   renumber, edit in place, or squash. Fix with a new migration. Any migration
   that `CREATE TABLE`s must also `ENABLE ROW LEVEL SECURITY` (Supabase PostgREST
   anon-key exposure otherwise).
4. **Never overwrite or delete facts** — close the validity window and link the
   replacement. Only exception: `mem_forget` (certified erasure).
5. **Every syscall writes an audit row**, including denials, misses, brownouts,
   errors. An early return skipping the audit write is a defect.
6. **Identity comes from the API key, resolved server-side.** Any code reading
   namespace/actor/role/team/scope from a request body is a bug regardless of use.
7. **Brownout over hard-fail** for backend/LLM/budget failures — but a policy
   check that couldn't run is a denial, never an allow.
8. **Drivers are read-only cartridges**: modules under `src/driver/` import only
   `src/types.js`, `src/retrieval/`, `src/embed/`. Enforced mechanically by
   `npx tsx src/cli.ts conformance <driver>`.
9. **Never weaken a test to make it pass**, and never fabricate command output —
   paste real output in PRs.

## Conventions (differ from defaults)

- Node 22, ESM: **relative imports end in `.js` even in TypeScript sources**
  (`import { foo } from "./bar.js"`). Not a typo.
- Strict TypeScript, no `any` unless unavoidable (say why in a comment).
- Shared types come from `src/types.ts` only — never another module's internals.
- DB access goes through the shared `Db` handle; never open your own pool.
- pgvector params bind as `'[0.1,0.2]'` strings via the `toVectorLiteral` helper.
- Boundary timestamps (HTTP/MCP/CLI/storage) are ISO-8601 strings, not epoch
  numbers or `Date`.
- The console (`kernel/console/`) is string-rendered with no framework and no
  build step; escaping untrusted values is manual and mandatory.
- Match the file you're editing: no reformat/import-reorder/style-only diffs
  mixed into behavior changes.

## Contribution boundaries

- PRs touching these are usually declined (in-house): `src/auth/`, `src/iam/`,
  `src/tenancy/`, `src/access-projection/`, `src/db/migrations.ts`,
  `src/audit/`, `src/policy/`, `src/security/`, `src/write/`,
  `src/conformance/`, and the driver contract (`src/driver/index.ts`,
  `src/driver/view.ts`). New driver cartridge files are welcome. Failing
  regression tests in those areas are extremely valuable — send them.
- Licensing: repo is AGPL-3.0-or-later except `src/driver/`, `src/mcp/`,
  `integrations/` (Apache-2.0). Code may move Apache→AGPL, **never** the reverse;
  don't refactor helpers "up" into permissive subtrees. No GPL-2.0-only deps.
  New dependencies need a licence note in the PR.
- Branch from `master`; commit format `area: imperative summary`
  (e.g. `write: close validity window on superseding fact`).
- Verification is proportional: focused tests for isolated changes; full
  `npm test` + typecheck + build (+ `test:pg` when SQL changed) for auth, ACL,
  tenancy, policy, audit, write path, MCP, migrations. Every behavior change
  needs a regression test.
- AI-assisted contributions are fine: read/understand every line, actually run
  it, and disclose agent involvement in the PR description.
