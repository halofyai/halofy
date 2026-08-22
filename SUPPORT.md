# Support

Where to take a question, a bug, or a vulnerability. Picking the right channel is
the fastest way to an answer.

| What you have | Where it goes |
|---|---|
| A question — how something works, whether it can do X, why it behaves this way | **GitHub Discussions** |
| A reproducible bug in this repository | **GitHub Issues** → bug report form |
| A security vulnerability | **Not a public issue.** See [`SECURITY.md`](SECURITY.md) |
| A feature idea | **GitHub Discussions**, before an issue |
| A conduct problem | <conduct@halofy.ai> — see [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) |
| Commercial licensing, or the AGPL not fitting your deployment | <licensing@halofy.ai> |
| An account, invoice, or hosted-service question | Your Halofy support channel, not this repository |

## Read first

Most questions are answered in the repository:

- [`README.md`](README.md) — what it is, and the no-credentials quickstart
- [`docs/README.md`](docs/README.md) — the documentation index
- [`docs/getting-started.md`](docs/getting-started.md) — zero to a working kernel
- [`docs/self-hosting.md`](docs/self-hosting.md) — deploying and operating it yourself
- [`docs/architecture.md`](docs/architecture.md) — how the pieces fit
- [`docs/driver-kit.md`](docs/driver-kit.md) — mounting your own retrieval engine
- [`OPEN-SOURCE-SCOPE.md`](OPEN-SOURCE-SCOPE.md) — what is open, what is commercial, and what stays that way

Searching closed issues and discussions is usually faster than waiting for a
reply.

## Filing a good bug report

Issues are for **reproducible defects**. The bug report form asks for what it
asks for because without those fields the report cannot be acted on:

- What you expected, and what happened instead
- The smallest reproduction you can manage — a failing test is ideal, since the
  suite is hermetic and needs no credentials
- Self-hosted or managed, and the version or commit
- Which retrieval driver is mounted
- Real, pasted output: the error, the stack, the command you ran

If it reproduces in `npm test` or `npm run demo`, say so and paste it. That path
requires no API key, no database and no network, which means we can reproduce it
exactly.

## Response expectations, honestly

The open build is **community-supported**. Maintainers read everything, but there
is no response-time commitment on issues or discussions, and no guarantee that
any particular bug gets fixed on a timetable that suits you. Security reports are
the exception and have their own acknowledgement target in
[`SECURITY.md`](SECURITY.md).

If you need a commitment — a response SLA, a fix window, or someone accountable
for your deployment — that is what the commercial offering is for:
<licensing@halofy.ai>. We would rather say that plainly than let you wait on an
issue thread that was never going to carry an obligation.

## Helping others

Answering someone else's discussion is the most useful thing in this project
after a good bug report. If an answer took you a while to work out, it belongs in
`docs/` — send the pull request.
