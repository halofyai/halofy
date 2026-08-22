# Security policy

Halofy is a memory kernel. Its whole job is to decide who may read which
sentence, to record that decision, and to be able to prove afterwards that it
did. That makes almost every interesting bug in this codebase a security bug.
We would rather hear about it from you than from a customer.

- **Report a vulnerability:** the repository's **Security → Report a vulnerability**
  (GitHub Private Vulnerability Reporting), or <security@halofy.ai> as a fallback.
- **Do not** open a public issue, discussion, or pull request for a vulnerability.
- **Do not** test against Halofy-operated infrastructure. Run your own instance —
  it needs no credentials and no network (section 7).

---

## 1. Supported versions

The project is pre-1.0. The version in `kernel/package.json` is the only version
number that means anything today.

| Version line | Status | Security fixes |
|---|---|---|
| `main` (latest commit) | Actively developed | Yes — fixes land here first |
| Latest tagged `0.x` release | Supported | Yes |
| Any earlier `0.x` release | Unsupported | No backports |
| Container images older than the latest tag | Unsupported | Rebuild from a supported tag |

"Supported" means: we will fix a confirmed vulnerability on `main` and cut a
release that contains the fix. It does **not** mean we will backport to an older
`0.x` line — before 1.0, the upgrade path is forward. When 1.0 ships, this table
gets a real maintenance window and this sentence goes away.

If you are running a fork or a patched build, we can still triage the report,
but the fix will be described against `main`.

---

## 2. How to report

**Preferred:** GitHub Private Vulnerability Reporting, from the repository's
Security tab. It gives us a private fork to develop the fix in, gives you a
thread that survives staff changes, and lets us publish the GHSA advisory — and
request a CVE — from the same place, without a separate handoff.

**Fallback:** <security@halofy.ai>. Use this if you cannot use GitHub, or if you
believe the vulnerability is in GitHub's handling of this repository itself.

### What to include

A report we can reproduce is worth ten reports we cannot. Please give us:

1. **What you attacked** — the syscall, HTTP route, console screen, connector, or
   driver, by path (for example `POST /v1/mem/search`, `kernel/src/index/index.ts`).
2. **The identity you used** — role (`owner` / `admin` / `auditor` / `member` /
   `agent`), namespace, and whether it was an API key or a console session. The
   entire access model is identity-relative; a finding without the caller's
   identity cannot be assessed.
3. **Reproduction steps** against a local instance. A failing test file in the
   shape of `kernel/test/cross-tenant.test.ts` is the single most useful artifact
   you can send, because it becomes the regression test.
4. **The impact you claim**, stated as what data crossed which boundary — not a
   scanner severity string.
5. **Version**: the release tag or commit SHA, plus whether you ran on PGlite
   (the dev default) or real Postgres. Some findings only exist on one.
6. **Your environment**: driver in use (`baseline`, `graph`, `mem0`), whether
   `ANTHROPIC_API_KEY` / `OPENAI_API_KEY` were set, and whether a sidecar was
   mounted.
7. **How you would like to be credited**, or that you would prefer not to be.

If you have a patch, send it. If you do not, send the failing test. Either is
enough; neither is required.

### Encryption

If you need to encrypt, say so in your first message to <security@halofy.ai> and
we will send you a key. We do not publish a static PGP key, because a published
key that nobody rotates is worse than no key at all.

---

## 3. What happens next, and when

These are **targets**, not contractual commitments. The open build is
community-supported (see [`SUPPORT.md`](SUPPORT.md)); security reports are the one
place we hold ourselves to a clock, and we will tell you when we are going to
miss it rather than go quiet.

| Stage | Target | What it means |
|---|---|---|
| Acknowledgement | **3 business days** | A human has read it and it is tracked. Not a verdict. |
| Triage verdict | **10 business days** | Confirmed / not-reproducible / out-of-scope / duplicate, with severity and reasoning. |
| Fix — Critical | **14 calendar days** from confirmation | Or a mitigation plus a stated date. |
| Fix — High | **30 calendar days** | |
| Fix — Medium | **90 calendar days** | |
| Fix — Low | Next convenient release | May be batched. |
| Public advisory | Within **7 days** of the fix being released | GHSA, with credit. |

**Disclosure.** We ask for coordinated disclosure and will work to the timelines
above. If we go silent for **45 days** after acknowledging your report, consider
yourself released from the embargo — a maintainer being unresponsive is our
failure, not a reason to sit on a live vulnerability. If you need to publish
sooner because the issue is being exploited, tell us and publish; we will not
treat that as bad faith.

**Duplicates.** First complete report wins. "Complete" means reproducible — a
vague earlier report does not pre-empt a working later one.

---

## 4. Scope

### In scope

Everything in this repository that enforces a boundary:

- **The kernel and its syscall layer** — `kernel/src/syscalls/`, `kernel/src/kernel.ts`.
- **ACL and tenant isolation.** Any path by which a caller in namespace `N` reads,
  infers the existence of, or writes to a row outside `N` and its `/`-split
  ancestors. This includes the sibling-tenant case, the crafted-namespace case
  (`acme%`, `acme_`, `acme\`), and the descendant case. `kernel/src/index/index.ts`,
  `kernel/src/tenancy/`, `kernel/src/access-projection/`.
- **The audit trail's integrity.** Anything that lets a syscall complete without
  its audit row, that suppresses or rewrites an existing row, or that lets the
  sha256 chain in `kernel/src/audit/index.ts` be forged so `verifyChain()` still
  returns `ok: true`.
- **Erasure and deletion certificates.** Forging a `DeletionCertificate`, making
  `verifyCertificate()` accept a tampered payload, or a `mem_forget` that reports
  erasure while data survives — including in the cold tier, the warm store, the
  L1 cache, or a driver's own state. `kernel/src/erasure/`.
- **Authentication and API key handling.** Key forgery or prediction, resolution
  of a revoked or expired key, session fixation or theft, the bootstrap path in
  `kernel/src/auth/index.ts`, the console session store in `kernel/src/console/auth.ts`.
- **Authorization between roles.** Any escalation across
  `agent` → `member` → `auditor` → `admin` → `owner` → root owner, or across the
  subtree fences `assertAdminScope` / `assertReadScope` in `kernel/src/http/adapter.ts`.
- **Credential encryption at rest.** `kernel/src/auth/bearer-cipher.ts`,
  `kernel/src/ingest/source-config.ts`, `kernel/src/cold/index.ts` — key
  derivation, AAD binding, nonce reuse, or any path that returns a plaintext
  secret to a client.
- **Console XSS and CSRF.** The console renders strings, not a framework; the
  escape primitive is `esc()` in `kernel/console/app.js`. An unescaped
  interpolation of attacker-controlled memory content, an actor name, a namespace,
  or a connector label is a valid finding. So is a state-changing route reachable
  cross-origin.
- **SSRF and injection in ingestion.** A DSN that reaches a link-local metadata
  endpoint past `assertSecurePostgresDsn()`, webhook signature or replay-window
  bypass, path traversal out of a connector's configured root, and anything in
  `kernel/src/ingest/` that lets an external source reach the store without
  passing the write path (D10).
- **The driver sandbox boundary.** A retrieval cartridge that reaches storage,
  the write path, or the audit log; or a static-scan bypass of
  `checkReadOnlySource()` in `kernel/src/conformance/index.ts`.
- **Data-classification enforcement** — restricted content escaping to a
  disallowed destination via `kernel/src/dlp/`.
- **Cryptographic misuse anywhere** — weak randomness for an identifier that is
  used as a secret, a non-constant-time comparison on a secret, a signature
  verified against a key the attacker supplies.
- **Dependency vulnerabilities** where you can show the vulnerable path is
  actually reachable from this code.
- **The published container image and `docker-compose.yml`** — for example a
  default that starts the kernel with a predictable secret or a world-readable
  volume.

### Out of scope

Not because they do not matter, but because a report about them will be closed:

- **The hosted Halofy service** (`*.halofy.ai`, the managed gateway, managed
  channels, the managed connector catalog). Those are not in this repository.
  Report them to <security@halofy.ai>, but under a different programme — the
  scope, the safe harbour, and the rewards in this document do not extend to
  them, and testing them is not authorized here.
- **Denial of service through resource exhaustion on a self-hosted deployment.**
  You control the machine. Large payloads, expensive queries, connection
  exhaustion, filling the cold-store volume, and unbounded concurrency are
  operator concerns. *Exception:* an **asymmetric** amplification — a small,
  low-privilege request that reliably costs the server orders of magnitude more,
  or that takes the process down permanently rather than degrading it — **is** in
  scope, because "brownout, never hard-fail" is a design promise.
- **Findings in the deliberately stubbed dev defaults.** `HashEmbedder` is not a
  cryptographic hash and is not meant to be; `StubLlm` does no reasoning and
  dispatches on marker strings; PGlite is an embedded single-process database.
  These exist so the project runs end-to-end with no API key and no network. That
  they are weak is the documented design, not a vulnerability. `kernel/src/config.ts`
  refuses to boot on PGlite in production (`assertSupportedDeployment`). A bug in
  *that refusal* is in scope; the weakness of the stubs is not.
- **An ephemeral erasure signing key.** If `HALOMEM_SIGNING_KEY` is unset the
  kernel generates a per-process key and prints a warning
  (`kernel/src/erasure/keys.ts`). Certificates then do not verify across restarts.
  That is documented and warned about; production boot rejects it.
- **Social engineering, phishing, or physical attacks** against Halofy staff,
  contributors, or users.
- **Missing hardening that is the operator's job**: TLS termination, network
  policy, OS patching, secret storage, backup encryption, the reverse proxy.
- **Self-XSS**, clickjacking on pages with no state-changing action, missing
  `SameSite=Strict` where `Lax` is used deliberately, or a missing header with no
  demonstrated impact.
- **Scanner output with no analysis.** An automated report that a dependency has
  a CVE, without showing the reachable path, will be closed.
- **Vulnerabilities requiring a compromised host, a root shell, or a malicious
  operator.** The operator is inside the trust boundary; see
  [`docs/security/threat-model.md`](docs/security/threat-model.md) §7.
- **Anything requiring the victim to install a hostile retrieval driver.**
  Installing an in-process cartridge is a code-trust decision equivalent to
  installing a dependency. A *sandbox escape by a driver that passes
  `conformance`* is in scope; a driver that never claimed to pass is not.

---

## 5. Bug bounty

### What this programme is, honestly

At launch this is a **coordinated-disclosure programme with recognition**, and
monetary awards are **discretionary**. We are not going to publish a rate card we
might not honour. What you are guaranteed is: a real human triage, a stated
verdict with reasoning, credit in the advisory and the release notes if you want
it, and safe harbour (§6).

If you need a guaranteed payout before you spend time, this programme is not
that, and we would rather you knew before you started than after.

### Severity tiers

Severity here is defined by **which boundary broke**, not by CVSS arithmetic. The
examples are drawn from this system so there is no ambiguity about where a
finding lands.

| Tier | The boundary that broke | Concrete examples in this system |
|---|---|---|
| **Critical** | Tenant isolation, audit integrity, erasure integrity, or authentication | • A caller in namespace `globex` obtains any content, entity, concept, pointer, or audit row belonging to `acme`, through any read path.<br>• A crafted namespace (`acme%`, `acme_`, `acme\`) matches a sibling's rows.<br>• A syscall completes with no audit row, or an existing row is suppressed, altered, or reordered while `AuditLog.verifyChain()` still returns `ok`.<br>• A forged `DeletionCertificate` passes `verifyCertificate()` against the trusted public key, or `mem_forget` returns a certificate for data that still exists.<br>• API key forgery, prediction, or resolution of a revoked/expired key.<br>• Remote code execution in the kernel process.<br>• Recovery of an at-rest credential without the KEK. |
| **High** | Authorization between roles, session integrity, the driver sandbox, or classification enforcement | • Stored or reflected XSS in the console that executes with a signed-in operator's session — for example memory content, an actor name, or a connector label reaching the DOM unescaped past `esc()`.<br>• A `member` or `agent` performing an `admin`/`owner` action, or reading another actor's activity where the reporting pin should have applied.<br>• `assertAdminScope` / `assertReadScope` bypass reaching a namespace outside the caller's subtree.<br>• A retrieval driver that passes `conformance` reaching storage, the write path, or `audit_log`.<br>• Session token theft or fixation; a session surviving user disablement or expiry.<br>• SSRF from connector configuration to a link-local metadata endpoint, or filesystem traversal out of a connection root.<br>• Webhook HMAC or replay-window bypass.<br>• `restricted` content reaching a destination `kernel/src/dlp/policy.ts` should have denied. |
| **Medium** | Confidentiality of metadata, integrity of a non-security control, or a bypass that needs a precondition | • An oracle that distinguishes "denied" from "miss" on the caller-facing surface, letting a tenant confirm the existence of a foreign row without reading it.<br>• Rate-limit or budget-cap bypass.<br>• CSRF on a state-changing console route.<br>• A missing audit row on a non-security-relevant path.<br>• Disclosure of another tenant's namespace names, actor identifiers, or row counts without content. |
| **Low** | Defence in depth | • Missing or weak security header with a plausible but unproven impact.<br>• Verbose error message disclosing internal structure.<br>• A timing difference with no demonstrated practical exploit.<br>• A non-constant-time comparison on a value that is not actually secret. |

### Awards

**Discretionary at launch.** The ranges below are what we would aim to pay for an
exceptional, fully-reproduced report in each tier — a ceiling we are working
toward, not an entitlement. The decision, and the amount, is made case by case at
triage and communicated in the triage verdict, so you never find out at the end.

| Tier | Recognition | Monetary (discretionary) |
|---|---|---|
| Critical | Advisory credit, release-note credit | up to **USD 2,000** |
| High | Advisory credit, release-note credit | up to **USD 500** |
| Medium | Advisory credit | up to **USD 150** |
| Low | Advisory credit | none |

Things we will say plainly rather than bury:

- If we cannot pay, we will tell you **at triage**, not after the fix ships.
- Only the **first complete** report of an issue is eligible.
- Awards are at Halofy's sole discretion and are not a contract. Nothing here
  creates an obligation to pay, and none of it changes the warranty disclaimer in
  [`LICENSE`](LICENSE).
- We cannot pay where sanctions or local law prohibit it.
- Halofy employees, contractors, and their immediate family are not eligible.
- Accepting an award does not transfer any right in your finding other than
  permission to describe it in the advisory.

### Beyond the bounty

Two things are worth more to us than a vulnerability report and are rewarded the
same way:

1. **A regression test.** Convert your finding into a test in `kernel/test/` in
   the style of `kernel/test/cross-tenant.test.ts`. It gets merged with your
   name on it and the bug never comes back.
2. **A hardening PR** on a control the threat model marks *partial*. See
   [`docs/security/threat-model.md`](docs/security/threat-model.md) §6 — those are
   pre-agreed, so no design argument is needed first.

---

## 6. Safe harbour

If you make a good-faith effort to follow this policy, Halofy will:

- **not** initiate or support legal action against you for your research,
  including under computer-misuse, anti-circumvention, or contract theories;
- **not** treat your research as a breach of any terms of service or licence you
  have with us;
- treat your report as **authorized** conduct under applicable computer-fraud law,
  and say so in writing to a third party if one comes after you for it;
- work with you if a third party (a hosting provider, an employer) raises a
  complaint about research conducted within this scope.

Good faith means: you stayed inside §4 *in scope*, you followed §7, you did not
access, modify, retain, or exfiltrate data belonging to anyone else, you did not
degrade anyone's service, and you gave us a reasonable chance to fix it.

This safe harbour covers **this repository and software you run yourself**. It
does **not** authorize testing against Halofy-operated infrastructure or against
any third party's Halofy deployment. We cannot grant permission over someone
else's servers, and we will not pretend otherwise.

We are not able to grant safe harbour on behalf of the upstream projects Halofy
depends on. If your finding is in a dependency, report it to them; tell us too if
it is reachable from here.

---

## 7. Rules of engagement

1. **Test your own instance.** `cd kernel && npm install`, then
   `npm run env:init && docker compose up --build` gives you the whole system
   with no credentials and no network dependency. Or `npm run demo` for the
   end-to-end story in one process.
2. **Never test against `*.halofy.ai`** or any deployment you do not own. If you
   believe you have found something in the hosted service, report it — do not
   confirm it against production.
3. **No volumetric testing.** No load generation, no fuzzing another party's
   endpoint, no automated scanner pointed at anything you do not run.
4. **Do not access, copy, or retain other people's data.** If you stumble into
   real data, stop immediately, do not read further, tell us in the report, and
   delete what you have. Say how much you saw.
5. **Do not persist.** No backdoors, no added accounts, no leaving a payload
   behind, no pivoting.
6. **One report per issue.** Do not split one bug across several reports; do not
   bundle unrelated bugs into one.
7. **No extortion.** A report conditioned on payment before disclosure is not a
   security report and voids safe harbour.
8. **Do not publish before the embargo ends** (§3), including proof-of-concept
   repositories, conference submissions, and screenshots.
9. **Automation is fine locally.** Run every fuzzer you like against your own
   container. Just do not send us raw scanner output as a finding (§4).

---

## 8. Security properties you can rely on

These are the guarantees the code is built to hold. They are stated precisely so
that a counterexample is unambiguously a bug — and so you know exactly what to
attack. Each is grounded in a specific file; the mechanism and its residual risk
are in [`docs/security/threat-model.md`](docs/security/threat-model.md).

**The ACL is an ancestor rule, enforced in the query layer.**
A caller in namespace `N` sees rows whose namespace is `N` or a `/`-split prefix
ancestor of `N`. Siblings are invisible. Descendants are invisible. This is
enforced in `kernel/src/index/index.ts` — `namespaceAncestors()` produces an exact
list that is bound into a parameterized `namespace IN (...)`, never a `LIKE`
pattern, so a namespace containing `_` or `%` cannot act as a wildcard. Where a
subtree predicate genuinely is needed (management scopes, read-scope projections),
it is an escaped-prefix `LIKE ... ESCAPE '\'`. Callers do not filter by namespace;
if a route handler or a read model does its own namespace filtering, that is the
bug.

**Identity is resolved server-side (D9).**
Namespace, actor, role and source scope come only from the credential the kernel
resolved — an API key hashed to sha256 in `kernel/src/auth/index.ts`, or an opaque
console session whose sha256 is what is stored in `kernel/src/console/auth.ts`.
Syscalls take a resolved `Identity`; they do not take a namespace or an actor.

The distinction to hold onto: a caller may never assert *its own* namespace,
actor, role, or team — that always comes from the resolved credential. A caller
may *name a target* on an administrative route (set a policy for `acme/eng`,
issue a key, run a scorecard), and every such route passes the target through
`assertAdminScope()` or `assertReadScope()` in `kernel/src/http/adapter.ts`,
which admit only the caller's own subtree (root owner excepted). A route that
takes a target without that check, or a syscall that takes an identity field
from a body, is a defect.

**Every syscall writes an audit row — including the ones that failed (D4).**
Denied, miss, brownout, and error outcomes all produce rows. The log exposes no
update and no delete method by construction (`kernel/src/audit/index.ts`), and
`mem_forget` is explicitly forbidden from touching `audit_log`
(`kernel/src/erasure/index.ts`). Each row carries `prev_hash` and `event_hash`
over a canonical digest, forming a sha256 chain whose head is held in
`audit_chain_state` under a row lock; `AuditLog.verifyChain()` recomputes the
whole chain and names the first sequence number that does not reconcile. Deleting
or editing a row in the database is therefore detectable, not silent.
*Precisely:* the chain makes tampering **evident**. It does not make it
**impossible** — someone with write access to Postgres can rewrite the chain and
the head together. Ship the log somewhere append-only if you need more.

**Denied and miss are distinguished in the audit, not to the caller.**
`MemReadResult.denied` is always `false` on the caller-facing result, so a caller
cannot probe for the existence of rows it may not see; the audit row still records
`denied` distinctly from `miss` (`kernel/src/syscalls/index.ts`).

**Never overwrite, never delete (D7).**
A conflicting fact does not replace its predecessor. The prior row's validity
window is closed via `closeValidity()` and the new row links back through
`supersedes` (`kernel/src/index/index.ts`). History is queryable, not lost.
The one governed exception is `mem_forget`, which exists so that erasure is
explicit, subtree-scoped, transactional, and certified — never incidental.

**Erasure produces a signed certificate you can verify without us.**
`mem_forget` resolves its target **downward** inside the caller's own subtree — a
target that is an ancestor or a sibling of the caller resolves to zero rows — then
in one transaction hard-deletes the rows, writes one tombstone per erased id, and
mints an ed25519-signed `DeletionCertificate`
(`kernel/src/erasure/index.ts`, `kernel/src/erasure/certificate.ts`). The payload
is canonicalized with recursively sorted keys before signing, so signer and
verifier hash identical bytes. `verifyCertificate()` requires an
**out-of-band trusted public key**: the key carried inline on the certificate is
signed descriptive metadata and is never a trust anchor. Set
`HALOMEM_SIGNING_KEY` in production — the kernel refuses to boot in production
without it, and warns loudly when it falls back to an ephemeral key in
development.

**Credentials are write-only to clients and encrypted at rest.**
Connector configuration is sealed with AES-256-GCM under a KEK and is returned to
clients as `REDACTED_SOURCE_CONFIG` — an empty object that discloses neither field
names nor values (`kernel/src/ingest/source-config.ts`). Agent bearer envelopes
are AES-256-GCM with the row's id, namespace, and actor bound in as AAD, so moving
an envelope onto a different authority row fails closed
(`kernel/src/auth/bearer-cipher.ts`). Cold-tier blobs are A256GCM
(`kernel/src/cold/index.ts`). Console passwords are scrypt with a per-user
16-byte salt, compared with `timingSafeEqual`; an unknown email is compared
against a module-load decoy hash so the work and the response shape are the same
either way, and login is not an account-existence oracle
(`kernel/src/console/auth.ts`). API-key authentication never uses the reversible
bearer envelope — only the sha256 of the key.

**Production boot fails closed.**
`assertSupportedDeployment()` in `kernel/src/config.ts` refuses serverless
runtimes outright, and in production requires `DATABASE_URL`,
`sslmode=verify-full` on any non-loopback DSN
(`kernel/src/security/postgres.ts`), the cold and source-config KEKs, the signing
key, and shared persistent cold storage. A production deployment cannot silently
fall back to the dev stubs.

**Brownout, never hard-fail — but never fail open.**
A failed embedder degrades search to the BM25-only lane; an unavailable non-baseline
driver falls back to `baseline` over the *same* `ScopedView` and the fallback is
audited; an LLM outage degrades writes to verbatim storage
(`kernel/src/syscalls/index.ts`). Degradation never widens visibility: every
fallback lane runs over the same ACL-scoped view as the lane it replaced. A
policy fetch that fails propagates as an error with its audit row — it never
silently resolves to a permissive default.

**No telemetry.** The kernel does not phone home. There is no analytics SDK, no
usage beacon, and no remote feature flag in the open build. The `telemetry` field
on a memory object (`last_accessed`, `access_count`, `fault_count`) is local
access accounting used for tier placement; it never leaves your database.
Outbound network calls happen only where you configured them: your model
provider, your embedding provider, a sidecar you mounted, and the sources your
connectors read.

---

## 9. Hardening a deployment

The threat model assumes a competent operator. The short version:

- Set `HALOMEM_SIGNING_KEY`, `HALOMEM_COLD_KEK`, and
  `HALOMEM_SOURCE_CONFIG_KEK` from your secret manager. Never from a file in the
  image.
- Use real Postgres with `sslmode=verify-full`. PGlite is for development.
- Terminate TLS in front of the kernel and set `secureCookies` so the session
  cookie is issued `Secure` and HSTS is sent.
- Keep the kernel off the public internet unless you need it there; it is an
  administrative surface as well as an API.
- Back up `audit_log`, `tombstones`, and `deletion_certificates` to somewhere the
  kernel's database user cannot write. That is what turns "tamper-evident" into
  "tamper-evident *and* recoverable".
- Rotate API keys; they carry no expiry unless you give them one.
- Read [`docs/self-hosting.md`](docs/self-hosting.md).

---

## 10. Where to read next

- [`docs/security/threat-model.md`](docs/security/threat-model.md) — assets, trust
  boundaries, adversaries, the specific attacks each can attempt, the control that
  stops each, and an honest list of the controls that are only partial.
- [`docs/architecture.md`](docs/architecture.md) — how the write path, placement,
  and delegated retrieval fit together, including the ACL ancestor rule with
  worked examples.
- [`docs/driver-kit.md`](docs/driver-kit.md) — the `ScopedView` contract and the
  six conformance checks, if you intend to attack the driver boundary.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) §5 — the non-negotiables that exist because
  of past security defects.
- [`GOVERNANCE.md`](GOVERNANCE.md) §5 — the locked decisions the security model
  rests on.

Security questions that are not vulnerability reports are welcome in GitHub
Discussions. Commercial support, including a contractual response SLA:
<licensing@halofy.ai>.
