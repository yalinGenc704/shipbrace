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
pair       → rules suggest every input × operation kind        (no model)
propose    → a model suggests ways in, and which records are   (optional)
             private ("ownership" claims, `verifyOwnership`)
verify     → rules decide each suggestion on its own terms     (no model)
review     → ten OWASP Top 10:2025 modules for the user
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
| `packages/guardrails/bench/` | **The benchmark.** Sample apps with a known answer key (`cases.ts`) and the grader (`grade.ts`). `test/bench.test.ts` ratchets the scores |
| `packages/guardrails/src/review/vulnerabilities.ts` | Known flaws in installed packages via OSV.dev (A03). Off unless a `VulnerabilitySource` is passed; the server passes one |
| `docs/legal/third-party-services.md` | What leaves the platform, what users must be told, draft privacy-policy text |
| `scripts/bench.ts` | Prints the benchmark scores: rules alone, perfect suggester, optionally a real model |

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
# all tests (expect 127 pass, 1 skipped -- symlinks need elevation on Windows)
node --experimental-strip-types --test packages/guardrails/test/*.test.ts packages/scaffold/test/*.test.ts server/test/*.test.ts

# review API on :3000. Set REVIEW_ROOT explicitly: npm runs workspace scripts
# from inside server/, so without it only that one folder is reviewed.
# PACKAGE_LOOKUP=off keeps it fully offline (no OSV.dev lookups).
REVIEW_ROOT="$PWD" npm start --workspace @aegis/server

# dashboard on :5173 (falls back to app/src/fixtures/review.json without the API)
npm run dev --workspace @aegis/app

# benchmark scores (add --model, with --env-file=.env, to include Claude; costs credit)
node --experimental-strip-types scripts/bench.ts

# compare review with and without a model (costs API credit)
node --experimental-strip-types --env-file=.env scripts/simulate.ts <folder>
```

`.env` holds `ANTHROPIC_API_KEY`. It is git-ignored and must stay that way. Never
print its value. Prepaid credits with auto-reload off, so it cannot overspend.

## Conventions that are load-bearing

- **No false "pass".** A checklist item may report `pass` only if a detector
  actually ran. No detector, or one that could not run (`not-applicable`), hands
  the item back to the user. There is a test for this.
- **Only proof is a risk.** Anything styled as a risk must be traced or be the
  problem itself. Unproven pattern hits are leads (`unproven`), never risks.
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

- **Benchmark (43 apps, 24 real problems, 20 safe decoys), 2026-10-01:** rules
  alone prove 21; a perfect suggester proves 23 (the extra two are ownership
  gaps, which only a suggester can raise); the real model matched the perfect
  suggester on the 31-app version; **zero** false alarms. Only miss: component
  props (a stored comment rendered as raw HTML) are not inputs, because that
  needs following data through the database; it appears under "worth a look".
- **Inputs recognised** (`inventory-ast.ts`): route params, query, body,
  headers, cookies, outbound responses, `req.file(s)` uploads, GitHub repository
  content (`getContent`/`getReadme`/`getBlob`/archives), and only the
  environment values an outsider controls (`OUTSIDER_ENV`: PR titles, branch
  names). Ordinary settings such as `DATABASE_URL` are trusted on purpose.
  File operations are judged by their first argument (the path) only.
- **The model's job (user decision, 2026-10-01):** pairing covers every
  input → operation claim, so the model's distinct contribution is ownership
  claims: judging which records are private. `verifyOwnership` decides them by
  rules: route requires sign-in, input reaches a query (even a parameterised
  one), nothing on the way asks who is signed in (`inventory.identities`).
  Asking at all counts as checking (errs to silence).
- **Data leaving the platform.** OSV.dev gets public package names + versions
  only (user approved 2026-10-01; CC-BY attribution shown via `ActionItem.notice`).
  The model gets code excerpts: `.js/.ts` files only, through `redact()`.
  Before 2026-10-01 excerpts were sent whole, `.env` files included. Disclosure
  before first send and per-user opt-outs are **not built** (no sign-up yet);
  see `docs/legal/third-party-services.md`.
- **Risks are proven; pattern hits are leads.** The sink pattern rules
  (`UNPROVEN_RULES` in `review/modules.ts`) judge how a line is written, not
  where its values come from, and fired on safe code. Their findings go to
  `ActionItem.unproven` ("Worth a look, not proven" on the dashboard), are
  never graded or counted as risks, and set the item to `needs-your-review`.
  The user chose this on 2026-10-01. Other rules (e.g. hardcoded keys) stay risks.
- The Claude proposer once **refused** (cyber usage policy) on a deliberately
  vulnerable test app. On 2026-10-01, with the defensive prompt and the
  ownership task, claude-opus-5-5 ran on all 31 benchmark apps with **no
  refusals** and matched the perfect suggester exactly (16 of 20 proven, 0
  false alarms, 29 suggestions, 16 confirmed). Do not work around a refusal.
- The verifier follows a value through any number of plain function calls,
  across files. It does not follow method calls (`obj.fn(x)`), and a helper
  name defined twice, unknown code, or destructured parameters make the
  claim `undecidable` (never `no-path`).
- 17 of 35 checklist items have no detector and are left to the user. The
  checklist follows OWASP Top 10:2025; the four items added for its new
  categories (A03 supply chain, A10 exceptional conditions) have no detector yet.
- No GitHub integration, persistence, or webhooks yet.

## Next steps

1. Treat stored content (database rows rendered later) as an input; today it
   shows only under "worth a look".
2. Before any second user: the disclosures and per-user switches in
   `docs/legal/third-party-services.md` section 4.
3. GitHub integration: review each push automatically (needs a GitHub App).
4. Remove or clearly deprecate the legacy exports above.

See `docs/architecture.md` for the reasoning behind these decisions.
