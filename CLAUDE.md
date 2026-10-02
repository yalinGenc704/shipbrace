# Aegis

A hosted platform that sits beside whatever LLM a developer uses to build a web
app, and handles security, architecture, and deployment so they can stay in the
design surface. An opt-in detailed mode lets them follow along in the code.

The user (product owner) is not a developer. Explain decisions in plain
language, lead with a recommendation, and surface product choices to them;
absorb engineering choices yourself.

## The one rule that defines the security review

**An LLM may suggest a way in. Only rules may decide it is real.**

```
inventory  → find routes, untrusted inputs, dangerous operations
enumerate  → rules find the paths they can on their own        (no model)
propose    → a model suggests ways in                          (optional)
verify     → rules decide each suggestion on its own terms     (no model)
review     → ten OWASP modules for the user
```

- Nothing a model says becomes a finding unless `verifyClaim` returns `valid`.
- `verifyClaim` must never consult a model. A confident wrong claim has to fail
  exactly as loudly as an obvious one.
- The enumerating pass runs *before* the model so its findings exist
  independently; a hostile repository cannot use the model to suppress them.
- The review must work with no model, no API key, and no cost.

## Layout

| Path | What it is |
| --- | --- |
| `packages/guardrails/src/analysis/ast.ts` | oxc-parser wrapper and tree helpers |
| `packages/guardrails/src/analysis/inventory-ast.ts` | **The inventory in use.** Routes, sources, sinks, sanitizers, assignments, functions, call sites |
| `packages/guardrails/src/analysis/verify.ts` | **The verifier.** Decides one claim, following values across functions and files |
| `packages/guardrails/src/analysis/oracle.ts` | Enumerating pass (`analyseTaint`), scoped to one route handler |
| `packages/guardrails/src/analysis/proposer.ts` | Provider-agnostic `AttackProposer`; Claude implementation |
| `packages/guardrails/src/review/` | `pipeline.ts` runs everything; `modules.ts` is the ten-module checklist; `checks.ts` holds project-level detectors |
| `packages/guardrails/src/rules/` | Per-file rules. `injection.ts` reuses the AST sink detection |
| `packages/scaffold/` | Generates new apps from composable modules; `auth` is a per-app setting |
| `server/` | Stateless review API (`GET`/`POST /api/review`) |
| `app/` | React dashboard rendering the checklist |
| `scripts/simulate.ts` | Reviews a folder with and without a model and reports the difference |

### Do not use these — they are legacy and still exported

- `buildInventory` / `findDoors` etc. from `analysis/inventory.ts` — the old
  regex inventory. It reads code inside string literals as real code. Only its
  **types** are current. Use `buildInventoryFromAst`.
- `confirmProposal` / `confirmAll` from `analysis/oracle.ts` — the old matcher.
  It only recognises paths the enumerating pass already found, so a proposal can
  never contribute. Use `verifyClaim`.

## Running things

Bun and Docker are **not installed** on this machine, so the Bun-based root
scripts fail (`npm test` → "'bun' is not recognized"). Use Node directly:

```bash
# all tests (expect 100 pass, 1 skipped -- symlinks need elevation on Windows)
node --experimental-strip-types --test packages/guardrails/test/*.test.ts packages/scaffold/test/*.test.ts server/test/*.test.ts

# review API on :3000. Set REVIEW_ROOT explicitly: npm runs workspace scripts
# from inside server/, so without it only that one folder is reviewed.
REVIEW_ROOT="$PWD" npm start --workspace @aegis/server

# dashboard on :5173 (falls back to app/src/fixtures/review.json without the API)
npm run dev --workspace @aegis/app

# compare review with and without a model (costs API credit)
node --experimental-strip-types --env-file=.env scripts/simulate.ts <folder>
```

`.env` holds `ANTHROPIC_API_KEY`. It is git-ignored and must stay that way. Never
print its value. Prepaid credits with auto-reload off, so it cannot overspend.

## Conventions that are load-bearing

- **No false "pass".** A checklist item may report `pass` only if a detector
  actually ran. No detector, or one that could not run (`not-applicable`), hands
  the item back to the user. There is a test for this.
- **No warnings on correct code.** Several fixed bugs were warnings about code
  that was already right (a key in an ignored `.env`; `spawnSync` with an
  argument array). These teach users to ignore the tool. Treat one as a defect.
- **Precision over coverage.** Missing a real path is a gap; inventing one is a
  defect. When in doubt, return `undecidable`, never `valid` and never "safe".
- **Redact at the boundary.** Excerpts pass through `redact()` before a finding
  exists, so a reported secret is never copied into logs or the UI.
- **Plain language in user-facing text.** Tests forbid the words taint, sink,
  sanitiz*, CWE, and payload in risk explanations.
- **Pin exact versions** in generated apps. Verify package versions against the
  registry rather than from memory.

## Current state and known gaps

- Uploaded files, repository content, and environment values are declared as
  input kinds but **not detected**. This matters for a product that ingests
  other people's repositories.
- The Claude proposer **refused** (cyber usage policy) on a deliberately
  vulnerable test app, even with the defensive prompt. It analysed clean code
  fine. Unreliable precisely when needed. Do not work around a refusal.
- The verifier follows a value one call deep into another function. Chains that
  continue further are not followed and come back unproven.
- 13 of 31 checklist items have no detector and are left to the user.
- No GitHub integration, persistence, or webhooks yet.

## Next steps

1. Detect uploaded files, repository content, and environment values as sources.
2. Generate claims without a model: a pattern catalogue, or pairing every source
   with every sink and letting the verifier decide (cheap because checking is).
3. Test the refusal across several vulnerable repositories to learn whether it
   is systematic.
4. Remove or clearly deprecate the legacy exports above.

See `docs/architecture.md` for the reasoning behind these decisions.
