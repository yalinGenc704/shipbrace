# Architecture

Why the system is shaped the way it is. For what exists and how to run it, see
`CLAUDE.md`. Items marked **planned** are design intent, not built.

## The seam: the repository, not the LLM (planned)

The product must work with whichever LLM the user has chosen. Integrating
per-vendor does not scale and breaks whenever a vendor ships a new client. So the
integration point is the repository, which every LLM coding tool already writes to:

```
user + their LLM  ->  repo  ->  git push  ->  GitHub App webhook
                                                   |
                                                   v
                                     platform: review -> gate -> deploy
```

GitHub and Cloudflare are the two prerequisite accounts because they are the two
systems the platform acts on. **Built today:** a stateless review API that reads a
local folder. **Not built:** GitHub App, webhooks, deploy, persistence.

## The security review

### Suggest freely, decide by rules

The review answers one question: does untrusted input reach a dangerous operation
without passing through validation or escaping? It is answered in five steps.

```
inventory  routes, untrusted inputs, dangerous operations, checks, calls
enumerate  paths the rules find on their own                 rules only
propose    ways in a model suggests trying                   optional
verify     each suggestion decided on its own terms          rules only
review     ten modules for the user
```

A model is good at imagining where to look and bad at being sure. Rules are the
reverse. So the model only ever *suggests*; a suggestion becomes a finding only if
`verifyClaim` returns `valid`, and `verifyClaim` never consults a model. A user who
cannot evaluate a vulnerability report must never be shown an unverified one.

### Why verify claims rather than match them

The first version enumerated every path and then checked whether a suggestion
appeared on that list. That made the model unable to contribute anything by
construction: it could only be recognised, never evaluated. A real run confirmed
it — four suggestions, three matched, zero new findings.

`verifyClaim` reverses the direction. Given a specific claim ("this input, on this
route, reaches that operation"), it follows the value itself. Checking one claim is
far cheaper than finding every path, and that asymmetry is what lets the verifier
follow values into helper functions in other files, which the enumerating pass
does not attempt. On a three-route test app, enumeration finds one bug; the same
rules, given claims, confirm a second one in a helper, clear a route that
validates its input, and reject an invented claim.

The enumerating pass is kept for two reasons: the review must work with no model,
key, or cost; and running it before the model means a hostile repository cannot use
the model to suppress a real finding.

### Verdicts

`valid` (real), `blocked` (a check stands in the way), `no-path` (they do not
connect), `not-found` (the claim names code that does not exist), `undecidable`
(could not follow it). `blocked` and `no-path` are kept distinct because only the
first tells a user their validation is working. `undecidable` is never reported as
safe: missing a real path is a gap, inventing one is a defect.

### Why parse instead of matching text

The text-based engine could not tell code from a string containing code. Reviewing
this repository, it reported fourteen high-severity problems; the most serious were
sample code inside string literals in a fixture generator and the scaffold. Parsing
with oxc-parser removed that class entirely: fourteen became one.

TypeScript 7's own parser was considered and rejected. It exposes its syntax tree
only under paths marked `unstable`, which is the wrong foundation for a security
tool.

## The model experiment

Recorded because the conclusion is easy to get wrong.

- A prompt casting the model as a penetration tester asking for attack values was
  **refused** under the cyber usage policy. It was also unnecessary: verification
  matches on route and operation and never reads an attack string. The prompt is
  now framed as the defensive review it actually is.
- Against the old matcher, the model added nothing. That was a property of the
  matcher, not the model, and is why the verifier exists.
- With the defensive prompt, the model analysed clean code but **refused on a
  deliberately vulnerable app** — the case where it is needed. Not yet known
  whether this is systematic.

The verifier accepts claims from anything, so the valuable half does not depend on
the model. Generating claims without one (a pattern catalogue, or pairing every
source with every sink) is the obvious next experiment.

## One finding set, two views

The dashboard's essentials and detailed views render the same risks. Detailed adds
locations and traced paths and can never reveal a problem the simpler view hid —
otherwise the user who trusts the tool most would be the least protected. The same
principle governs `renderAuto()` and `renderSupervise()` in the engine.

## The checklist is honest about its own coverage

The ten modules are the OWASP Top 10:2025 in OWASP's order, so the priority
reflects measured prevalence and "did we cover everything" has an external answer.
The checklist moved from the 2021 edition on 2026-10-01. Item ids did not change
when items changed module (server-side request forgery joined access control;
supply-chain items left integrity), so a user's review ticks carry over.

An item may report `pass` only if a detector actually ran. An item with no detector,
or whose detector could not run here (no compose file to read, no passwords to
check), is handed back to the user with the reason. A false "pass" is worse than no
report: it tells the user to stop looking where they still need to. Today 18 of 35
items have a detector.

## Confidence gates automation

`certain` findings may be fixed automatically; `likely` ones block deployment at
critical or high severity but ask rather than act; `possible` ones are shown and
never block on their own. `blocksDeploy()` is the single place this policy lives.

## Handling untrusted code

Everything scanned is someone else's code and must be treated as hostile.

- **Never executed or imported.** Analysis reads and parses only.
- **Reads are confined.** A requested path is resolved, symlinks followed, and the
  result required to sit under a configured root. Reads are capped in files and bytes.
- **No shell.** git is invoked with an argument array and `shell: false`.
- **Errors do not leak.** API errors carry fixed messages; host paths go to the log.
- **Redact at the boundary.** Excerpts are redacted before a finding exists, so the
  system reporting a leaked key never copies it into logs or the UI.

**Open item.** An earlier version of this document required any rule needing a real
parse to run in a sandbox with no network and a time limit. Parsing now happens
in-process and unsandboxed. Parsing does not execute code, which removes the main
risk, but oxc-parser is native code fed hostile input, and a parser bug is a real
possibility. Before reviewing repositories from untrusted users, parsing should move
into an isolated worker with a time and memory limit.

## Secrets custody (planned)

Hosting means holding GitHub and Cloudflare tokens for every user.

1. GitHub App installation tokens only: one-hour expiry, minted per operation.
2. Cloudflare tokens scoped per user, encrypted at rest with a per-tenant key, and
   never returned by any API route.

## Deviations from the original stack spec

Verified against the registry on 2026-08-28:

- **TypeScript 7.0.2**, not 6.0β — 6.0.0-beta is a superseded prerelease.
- **Vite 8.2.2 stable**, not beta.
- **Bun 1.4 / `oven/bun:1.4`**, not 1.3.10.
- **SheetJS from the vendor CDN**, not npm `xlsx@0.18.5`, which is abandoned there
  and carries prototype-pollution and ReDoS advisories.
- **oxc-parser** added for analysis, from the same project as OxLint and Oxfmt.
- `postgres:18-alpine` confirmed present; unchanged.
