# Licensing

Everything in this repository is under one of two licences. Which one applies
depends on the directory, and the rule is mechanical.

| | Licence | Applies to |
|---|---|---|
| Kernel and console | **AGPL-3.0-or-later** ([LICENSE](LICENSE)) | Everything not listed below |
| Permissive subtrees | **Apache-2.0** ([LICENSE-APACHE-2.0](LICENSE-APACHE-2.0)) | `kernel/src/driver/`, `kernel/src/mcp/`, `kernel/integrations/` |

[NOTICE](NOTICE) is the authoritative list of the permissive subtrees. Each of
them also carries its own `LICENSE` file, so the licence travels with the code
if someone vendors a single directory.

Trademarks are granted by neither licence. See [TRADEMARK.md](TRADEMARK.md).

---

## 1. Why AGPL for the kernel

The kernel is the part that could be taken, wrapped in a hosted service, and
sold without any of the improvements coming back. AGPL-3.0 closes that gap: if
you modify Halofy and let other people interact with it over a network, the
people using it are entitled to your modified source.

That obligation is the point. It is also the thing some organizations cannot
accept — which is why section 3 exists.

**What AGPL does not do to you:**

- Running the unmodified kernel inside your company, for your own agents, over
  your own network, triggers no obligation to anyone outside it. Section 13 of
  the AGPL is about *modified* versions offered to *remote users*.
- Calling the HTTP API or the MCP server from your application does not make
  your application a derivative work of the kernel. Your application is a
  client. The wire protocol is not a licence boundary you can cross by
  accident.
- Writing a retrieval cartridge or an MCP client does not relicense your
  application, because those interfaces live in Apache-2.0 subtrees.

**What AGPL does do:**

- If you fork the kernel, change it, and offer it to users over a network, you
  must offer those users the corresponding source of your modified version,
  under AGPL-3.0-or-later.
- If you distribute a modified kernel — as a container image, an appliance, a
  binary — the same applies.

If you are unsure whether your deployment triggers the obligation, the answer is
usually "you modified it and other people use it over a network". Ask a lawyer,
not us; we are not able to give you legal advice about your own deployment.

## 2. Why Apache-2.0 for the subtrees

Three directories are deliberately permissive so that building *against*
Halofy never contaminates what you build:

- **`kernel/src/driver/`** — the `RetrieverDriver` interface, the `ScopedView`
  contract, and the reference cartridges. A retrieval engine you mount is
  yours. If this were AGPL, writing a cartridge for a proprietary retriever
  would be a licensing problem instead of an afternoon's work, and delegated
  retrieval (D1) would be delegated in name only. See
  [docs/driver-kit.md](docs/driver-kit.md).
- **`kernel/src/mcp/`** — the MCP server and tool definitions. Client and
  protocol code should be as free to embed as a client library.
- **`kernel/integrations/`** — editor and agent integrations, which by
  definition live inside somebody else's application.

The licence boundary is **one-way**, and this is the single rule most likely to
be broken by an otherwise good refactor:

> Code may move from an Apache-2.0 subtree into the AGPL kernel. Code must
> never move from the AGPL kernel into an Apache-2.0 subtree.

Hoisting a shared helper "up" into `kernel/src/driver/` silently relicenses
AGPL code as Apache-2.0. Halofy can relicense code it owns; a contributor
cannot relicense anyone else's. The pull request template has a checkbox for
this, and reviewers are expected to actually check it.

## 3. The commercial licence

Halofy is dual-licensed. If AGPL-3.0's network copyleft is incompatible with
how you need to ship — you embed the kernel in a proprietary product, or you
offer a modified version as a service and cannot publish your modifications —
a commercial licence removes the copyleft obligation for the same code.

Contact <licensing@halofy.ai>. Include what you are building, whether you are
modifying the kernel, and whether it is offered over a network.

This is the only reason contributions require a CLA. Halofy can only offer
those alternative terms for code it has the rights to relicense, and it acquires
those rights through the CLA. See [CLA.md](CLA.md), which also states plainly
what the CLA does *not* do: it does not let Halofy retract what is already
published under the AGPL. Every release already made stays available under the
licence it was published with.

The commercial licence changes your obligations for the same code. It is not a
different, better build, and it does not unlock features — see
[OPEN-SOURCE-SCOPE.md](OPEN-SOURCE-SCOPE.md) section 2.10 on why there is no
edition flag to unlock.

## 4. Third-party dependencies

The kernel's runtime dependency tree is permissively licensed. A scan on
2026-08-22 of the production closure of `kernel/package.json` found: MIT (209),
Apache-2.0 (27), ISC (12), BSD-2-Clause (7), BSD-3-Clause (4), BlueOak-1.0.0
(2), one `(MIT AND Zlib)`, and three dual-licensed packages where we elect the
permissive option: `(MIT OR GPL-3.0-or-later)` → MIT, `(AFL-2.1 OR
BSD-3-Clause)` → BSD-3-Clause, and one package whose manifest says only `BSD`
(its LICENSE file is BSD-3-Clause). One package declares no licence field in
its manifest; its LICENSE file is Apache-2.0. No dependency imposes a copyleft
obligation on the runtime tree once those elections are made, so nothing
upstream adds obligations beyond the AGPL choice made here.

Verify it yourself rather than taking the sentence above on faith:

```bash
npx license-checker-rseidelsohn --production --start kernel --summary
```

New dependencies are reviewed for licence compatibility. A GPL, LGPL, SSPL,
BSL, or "source available" dependency in the runtime tree is a blocking review
comment: it either changes what downstream users may do, or it is not open
source at all.

## 5. Contributing under these terms

Contributions are accepted under the licence of the directory they land in, and
under the CLA. In practice:

- A change to `kernel/src/write/` is AGPL-3.0-or-later.
- A change to `kernel/src/driver/` is Apache-2.0.
- Do not paste code from another project into either tree without checking its
  licence and its provenance, and say where it came from in the pull request.
- Do not add a file header claiming a different licence from its directory.

See [CONTRIBUTING.md](CONTRIBUTING.md).

## 6. Questions this document does not answer

We are not going to guess at your deployment for you, and nothing here is legal
advice. But two questions come up constantly and have short answers:

- *"Can I use Halofy inside my company without publishing anything?"* — Yes,
  including modified, as long as you are not offering the modified version to
  users outside your organization over a network.
- *"Does the AGPL apply to the data in my kernel, or the prompts and agents
  that call it?"* — No. The licence covers this software, not the memories you
  store in it, the models you route to, or your own agent code.

Anything harder than that: <licensing@halofy.ai>.
