# Halofy Trademark Policy

Version 1.0 — effective 2026-08-22
Questions: <licensing@halofy.ai>

## 1. What this document covers

The code in this repository is free software. The names and logos are not.

This policy covers the **Halofy Marks**:

| Mark | Type |
|---|---|
| **Halofy** | word mark |
| **HaloMem** | word mark |
| The Halofy logo, in any colourway (`kernel/console/assets/marks/`) | design mark |
| Any confusingly similar word or design, including transliterations, misspellings, and translations | — |

Neither of the licences in this repository grants you any right to use the
Halofy Marks:

- **Apache License 2.0, section 6** withholds trademark rights expressly: *"This
  License does not grant permission to use the trade names, trademarks, service
  marks, or product names of the Licensor."*
- **AGPL-3.0** is a copyright licence. It grants copyright and patent
  permissions and is silent on trademarks; section 7(e) explicitly contemplates
  a licensor declining to grant trademark rights. It does not grant any.

So your right to *copy, modify, run and redistribute the code* comes from the
licences. Your right to *call the result "HaloMem"* comes from this document,
and from nowhere else.

This policy grants rights. It does not take any away that trademark law already
gives you — in particular, nothing here restricts nominative fair use,
comparative advertising, commentary, criticism, or news reporting.

## 2. Uses that are always allowed, with no permission needed

You may, without asking:

1. **Say true things.** Use the word marks in plain text to refer accurately to
   this project: *"built on HaloMem"*, *"a HaloMem cartridge"*, *"we migrated
   from HaloMem to X"*, *"HaloMem does not support Y"*.
2. **Redistribute unmodified builds under their own name.** If you ship the
   software substantially as we published it — same source, same behaviour, only
   packaging or configuration changed — keep the name, keep the logo, keep this
   file.
3. **Package it.** Publish it to a distribution, registry, or package manager
   under the upstream name, following that ecosystem's naming conventions
   (`halomem-kernel`, `homebrew/halomem`, `halomem-git`, and so on).
4. **Run it as a service for yourself**, including internally at a company or
   for clients, and say what you are running.
5. **Write about it.** Books, courses, talks, blog posts, tutorials, benchmarks,
   comparisons, and academic papers. You may use the word marks in the title.
   You may reproduce the logo to illustrate the subject.
6. **State that your fork is a fork.** See section 3.
7. **Say you are compatible.** *"Works with HaloMem"*, *"HaloMem-compatible"*,
   *"implements the `halomem-driver/v1` interface"* — as long as it is true and
   the sentence makes clear whose product yours is.

In every case: use the marks as **adjectives applied to your own noun**, in the
same typeface as the surrounding text, and no more prominently than your own
name.

## 3. Forks and modified versions

You may fork. That is the point of AGPL.

**If you distribute a modified version, you must not present it as HaloMem.**
Concretely:

- Give it its own name. Do not use "Halofy" or "HaloMem" as the first or
  dominant word: `HaloMem Enterprise`, `HaloMem Pro`, `Halofy Cloud` and
  `HaloMemDB` are not available to you.
- Do not use the Halofy logo as your product's logo, icon, favicon, or app-store
  artwork. Replace the files in `kernel/console/assets/marks/`. The console
  degrades to a text wordmark when they are absent
  (`kernel/src/branding/halo-page.ts`).
- Do **say clearly** what you forked, and prominently. All of these are fine and
  encouraged:
  - *"Acme Recall — a fork of HaloMem"*
  - *"Acme Recall is derived from the HaloMem organizational memory kernel"*
  - *"Based on HaloMem by Halofy"*
- Do not describe your fork as "official", "certified", "supported by Halofy",
  "endorsed", or "the enterprise edition of HaloMem".
- Route your own bugs. Do not point users at Halofy support channels for a build
  we did not produce.

This is the standard AGPL fork bargain: the code is yours to change, the
reputation attached to the name is not.

## 4. Uses that are not allowed

Without written permission from Halofy:

1. **Naming a competing hosted service after the marks.** You may run HaloMem as
   a service. You may not call that service "HaloMem Cloud", "Hosted HaloMem",
   "HaloMem-as-a-Service", or anything a customer would read as Halofy's own
   offering. Name your service after yourself and say truthfully that it runs
   HaloMem.
2. **Using the marks in your company name, product name, app name, or brand.**
3. **Domain names, social handles, and repository/organisation names** whose
   dominant element is a Halofy Mark — `halomem.io`, `gethalomem.com`,
   `@halomem_official`, `github.com/halomem-cloud`. A subdomain or path of your
   own domain that describes what you do is fine: `acme.com/halomem-hosting`.
4. **Modifying the logo** — recolouring, redrawing, adding elements, embedding it
   in another mark, or using it as a design element in your own identity.
5. **Merchandise** bearing the marks for sale.
6. **Any use that implies endorsement, affiliation, certification, partnership,
   or origin** where none exists. This is the rule the other five are examples
   of.
7. **Registering** any Halofy Mark, or anything confusingly similar, as a
   trademark, domain, or company name in any jurisdiction.

## 5. Logo files

The logo files in `kernel/console/assets/marks/` are included so that a person
running an unmodified build sees a working console, and for the illustrative
uses permitted in section 2. They are **not** licensed under AGPL-3.0 or
Apache-2.0 and are not covered by either grant.

Do not stretch, rotate, recolour, crop, outline, add effects to, or place the
logo on a low-contrast background. Leave clear space around it of at least the
height of the mark's own cap-height.

## 6. Third-party marks in this repository

This repository refers to products owned by others — Anthropic, OpenAI,
Microsoft/Azure, Google, Slack, Notion, Obsidian, PostgreSQL, Docker, Mem0, and
others. Those marks belong to their owners and are used here nominatively, to
identify the systems HaloMem interoperates with. Nothing in this repository
claims any right in them or implies their endorsement of HaloMem.

If you own a mark used in this repository and want the reference changed or
removed, write to <licensing@halofy.ai> and we will act.

## 7. Asking for permission

Anything not permitted above is available by agreement. Write to
<licensing@halofy.ai> with what you want to do, where the mark will appear, and
for how long. We answer.

If you are unsure whether your use is permitted, ask before you print it.

## 8. Changes

Halofy may revise this policy. Revisions are not retroactive: a use that was
permitted when you started it stays permitted for a reasonable transition
period, which will not be less than 90 days from the date the revision is
published in this repository.
