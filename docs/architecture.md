# Architecture

## The seam: GitHub, not the LLM

The product must work with whichever LLM the user has chosen. Integrating per-vendor
does not scale and breaks whenever a vendor ships a new client. So the integration
point is the **repository**, which every LLM coding tool already writes to:

```
user + their LLM  ->  local repo  ->  git push  ->  GitHub App webhook
                                                        |
                                                        v
                                          platform: scan -> gate -> deploy
```

The platform never talks to an LLM on the user's behalf and never needs to know which
one they used. This is also why the two prerequisite accounts are GitHub and Cloudflare:
they are the two systems the platform acts on, via delegated access.

## Packages

| Package | Role |
| --- | --- |
| `packages/guardrails` | Pure finding engine. No IO, no network. Runs identically in the server, a worker, and tests. |
| `packages/scaffold` | Generates the opinionated stack with secure defaults already wired. |
| `server` | Hono on Bun. GitHub App webhooks, scan orchestration, deploy control, API for the dashboard. |
| `app` | React 19 dashboard. Design surface plus the supervise view. |

`guardrails` has no dependencies on the others by design: it is the piece most likely
to be reused (CI action, CLI, future MCP server) and the piece that must be easiest to
audit.

## One finding stream, two views

Background mode and supervise mode are `renderAuto()` and `renderSupervise()` over the
*same* `Finding[]`. They are not two rule sets. If supervise mode could reveal a problem
that background mode hid, the safe-by-default promise would be false, and the user who
trusts the tool most would be the least protected.

- `renderAuto` returns plain language and no code or file paths.
- `renderSupervise` adds the line, the rule id, the confidence, and the reasoning.

A test asserts that auto-mode output contains no file paths.

## Confidence gates automation

Every finding carries `confidence`. It governs how much the platform may do silently:

- `certain` — eligible for automatic fixing.
- `likely` — blocks deploy at `critical`/`high`, but asks rather than acts.
- `possible` — surfaced, never blocking on its own.

`blocksDeploy()` is the single place this policy lives, so it can be tuned in one edit
and tested directly.

## Secrets custody (the cost of hosting)

Hosting means the platform holds GitHub installation tokens and Cloudflare API tokens
for every user. Consequences accepted up front:

1. **No long-lived GitHub tokens.** Use GitHub App installation tokens, which expire
   in one hour and are minted per operation.
2. **Cloudflare tokens are scoped per user account**, encrypted at rest with a
   per-tenant key, and never returned by any API route — write-only from the UI.
3. **Scanning runs on untrusted code.** Rules are regex-over-text and never execute or
   import user code. Any future rule that needs a real parse must run in a sandbox with
   no network and a wall-clock limit.
4. **Findings are logged.** Everything user-visible passes through `redact()` first, so
   a leaked key is not copied into logs by the system reporting the leak.

## Deviations from the original stack spec

Verified against the registry on 2026-08-28:

- **TypeScript 7.0.2**, not 6.0β — 6.0.0-beta is a superseded prerelease.
- **Vite 8.2.2 stable**, not beta — 8.x reached stable.
- **Bun 1.4 / `oven/bun:1.4`**, not 1.3.10 — several patches behind.
- **SheetJS from the vendor CDN**, not npm `xlsx@0.18.5`, which is abandoned on the npm
  registry and carries prototype-pollution and ReDoS advisories. Shipping it in every
  generated app would make the tool's own guardrails fail on the tool's own output.
- `postgres:18-alpine` confirmed present; unchanged.
