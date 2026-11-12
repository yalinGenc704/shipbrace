# ShipBrace

A hosted platform that sits beside whatever LLM a developer uses to build a web
app, and handles security, architecture, and deployment so they can stay in the
design surface. An opt-in detailed mode lets them follow along in the code.

Working notes for anyone (person or coding agent) changing this codebase:
what exists, how to run it, the rules that must not be broken, and what is
known to be missing. The reasoning behind the design is in
`docs/architecture.md`; the overview for readers is `README.md`.

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
- **One opt-in exception (Murat's decisions, 2026-11-10; live since
  2026-11-11):** with `ReviewOptions.cleanerJudge` set (off by
  default in the library; on Cloudflare it is the outside step `judge`, on
  only for `AI_ALLOWED_GITHUB_IDS` with the installation's AI switch and
  `AI_CLEANER_CHECK` on, model `CLEANER_MODEL` = Haiku 5.5), a model reads
  the app's own cleaning functions on traced
  paths (`analysis/cleaners.ts`, `analysis/cleaner-judge.ts`). When it says
  a cleaner the rules trusted does not work, the rules re-trace the path
  without that one cleaner, and only a path still open becomes a risk,
  `confirmedBy: "cleaner-check"`, worded as the AI's reading; this can turn
  a check red. When it says a cleaner the rules did not see works, a traced
  risk becomes "worth a look" (never silence or a pass), worded as an
  opinion; the GitHub check is then neutral, never green
  (`server/src/github/report.ts`, counting `cleaner/` leads). A hostile
  repository can still steer the model towards "works" and so turn a red
  check neutral; the guarantee above holds in full only with the step off.
  The questions cross the wall from the side that reads the repository, so
  the side with the key checks them (`parseQuestions`: at most 30, ids
  `q1`..., a plain name, code capped at 4,000 characters, secrets hidden
  again) and sends nothing malformed. A cleaner is asked about only when
  every value the operation uses goes through it, in the same handler; when
  the function's name is bound exactly once in its file (a top-level
  definition or an import from this repository; parameters, local
  look-alikes and later writes count as bindings) and never written; and,
  for `const x = clean(v)`, when `x` is bound once in the handler and never
  written. The re-trace uses `analyseTaint`, so a cleaned path found only by
  pairing or a proposal (across functions) is never turned into a finding.

## Layout

| Path | What it is |
| --- | --- |
| `packages/guardrails/src/analysis/ast.ts` | oxc-parser wrapper and tree helpers; `codeOnly` (a file with comments and quoted prose blanked) |
| `packages/guardrails/src/analysis/fixed-text.ts` | Proves a value pasted into a query is fixed text (`?` marks, a fixed `const`) |
| `packages/guardrails/src/analysis/inventory-ast.ts` | **The inventory in use.** Routes, sources, sinks, sanitizers, assignments, functions, call sites |
| `packages/guardrails/src/analysis/verify.ts` | **The verifier.** Decides one claim, following values across functions and files |
| `packages/guardrails/src/analysis/oracle.ts` | Enumerating pass (`analyseTaint`), scoped to one route handler |
| `packages/guardrails/src/analysis/proposer.ts` | Provider-agnostic `AttackProposer`; Claude implementation |
| `packages/guardrails/src/analysis/cleaners.ts`, `cleaner-judge.ts` | The optional cleaner step: the app's own cleaning functions on traced paths, judged by a model (`CleanerJudge`; Claude implementation, `parseQuestions`/`toVerdicts` for crossing the wall) |
| `packages/guardrails/src/review/` | `pipeline.ts` runs everything; `modules.ts` is the ten-module checklist; `checks.ts` holds project-level detectors |
| `packages/guardrails/src/rules/` | Per-file rules. `injection.ts` reuses the AST sink detection |
| `packages/scaffold/` | Generates new apps from composable modules; `auth` is a per-app setting |
| `server/` | Review API (`GET`/`POST /api/review`), GitHub webhook, kept reviews (`/api/reviews/:id`, `/api/history/:id`); serves `app/dist` when built |
| `server/src/sandbox/` | **Every review runs here**, in a sealed child process: no secrets, no network, reads limited to ShipBrace's code, time and memory limits |
| `cloud/` | **Where it runs: Cloudflare, live at https://app.shipbrace.com.** Worker (`src/index.ts`: webhook, queue job, kept-review API, dashboard assets), one review in a container (`src/review-container.ts`), daily limits counted at each start (`src/limits.ts`), reviewer container class with internet off (`src/reviewer.ts`; the outside steps `propose`, `judge`, `lookup` and their checks are in `src/outside-steps.ts`), D1 history (`src/history-d1.ts`, `migrations/`), `wrangler.jsonc`. `wall-check/` re-proves the internet wall |
| `Dockerfile`, `deploy/` | **Hosting.** One image, two roles (server, reviewer); `deploy/compose.yaml` runs shipbrace, reviewer, postgres, backup, cloudflared; `deploy/README.md` is the server setup guide |
| `server/src/history.ts` | Review history in PostgreSQL: schema migrations, save, read back by unguessable link |
| `app/` | React dashboard: the live review at `/`, a kept review at `/reviews/:id`, a repository's history at `/history/:id` |
| `scripts/simulate.ts` | Reviews a folder with and without a model and reports the difference |
| `packages/guardrails/bench/` | **The benchmark.** Sample apps with a known answer key (`cases.ts`) and the grader (`grade.ts`). `test/bench.test.ts` ratchets the scores |
| `packages/guardrails/src/review/vulnerabilities.ts` | Known flaws in installed packages via OSV.dev (A03). Off unless a `VulnerabilitySource` is passed; the server passes one |
| `docs/legal/third-party-services.md` | What leaves the platform, what users must be told, draft privacy-policy text |
| `README.md` | Plain-language overview for anyone: the vision, how a review decides, the rules, honest numbers, what is built |
| `scripts/bench.ts` | Prints the benchmark scores: rules alone, perfect suggester, optionally a real model |
| `scripts/bench-cleaners.ts` | The cleaner experiment on the benchmark, per model and run, with token cost (costs credit) |

### Removed legacy (2026-10-20)

The old regex inventory (`buildInventory`, `findDoors`, `findAssignments`...)
and the old matcher (`confirmProposal`, `confirmAll`) are gone: the regex
version read code inside string literals as real code, and the matcher could
never let a proposal contribute. `analysis/inventory.ts` now holds only the
shared types; build an inventory with `buildInventoryFromAst` and decide
claims with `verifyClaim`.

## Running things

Development is on a Mac (Bun installed but unused; Docker through Colima). ShipBrace
itself still runs on Node; the Bun-based root scripts are untested. Node works
everywhere:

```bash
# PostgreSQL 18 (Homebrew, not started at login). Databases: shipbrace, shipbrace_test.
LC_ALL=en_US.UTF-8 /opt/homebrew/opt/postgresql@18/bin/pg_ctl -D /opt/homebrew/var/postgresql@18 -l /opt/homebrew/var/log/postgresql@18.log start

# all tests (expect 431 pass). Without TEST_DATABASE_URL the 6 database tests
# are skipped and say so; it must name a database ending in _test (it is wiped).
# CI (.github/workflows/ci.yml) runs typecheck, lint, tests and build on every push.
TEST_DATABASE_URL=postgres:///shipbrace_test npm test
npm run typecheck && npx oxlint .

# review API on 127.0.0.1:3000 (this machine only; HOST changes it, and folder
# reviews answer only requests addressed to localhost). Set REVIEW_ROOT explicitly: npm runs workspace scripts
# from inside server/, so without it only that one folder is reviewed.
# PACKAGE_LOOKUP=off keeps it fully offline (no OSV.dev lookups).
# Build the dashboard first so the server serves it (links from GitHub checks).
npm run build --workspace @shipbrace/app
REVIEW_ROOT="$PWD" node --experimental-strip-types --env-file=.env server/src/index.ts

# dashboard on :5173 (falls back to app/src/fixtures/review.json without the API)
npm run dev --workspace @shipbrace/app

# benchmark scores (add --model, with --env-file=.env, to include Claude; costs credit)
node --experimental-strip-types scripts/bench.ts

# the cleaner step on the benchmark: Haiku 5.5 and Opus 5.5 reading home-made cleaners (costs credit)
node --experimental-strip-types --env-file=.env scripts/bench-cleaners.ts --runs 3 --models haiku,opus
# the same step on the local review API: add AI_REVIEW=on AI_CLEANER_CHECK=on (not with REVIEWER_SOCKET)

# the hosted setup on this Mac (Colima runs Docker; `colima start` first).
# Throwaway values only in deploy/.env and deploy/secrets/; delete afterwards.
cd deploy && docker compose -f compose.yaml -f compose.local-test.yaml up -d --build

# compare review with and without a model (costs API credit)
node --experimental-strip-types --env-file=.env scripts/simulate.ts <folder>
```

`.env` holds `ANTHROPIC_API_KEY`, the GitHub App settings (`GITHUB_APP_ID`,
`GITHUB_PRIVATE_KEY_PATH`, `GITHUB_WEBHOOK_SECRET`), `DATABASE_URL`
(`postgres:///shipbrace` here; no password over the local socket) and, while a
tunnel is open, `PUBLIC_URL` (its address, for links in checks); the App's key file is
`github-app.pem`. All are git-ignored and must stay that way: on a new machine
they are recreated, never copied through chat or GitHub. Never print their
values. `GITHUB_PRIVATE_KEY_PATH` must be absolute: the server resolves it from
wherever it starts, which is `server/` under `npm start --workspace`. Prepaid
credits with auto-reload off, so it cannot overspend.

The practice apps used for outside validation are not in this repository;
re-clone them read-only (never install or run them) into `~/shipbrace-test-repos`:
appsecco/dvna, OWASP/NodeGoat, juice-shop/juice-shop. To review one through
the server with the AI step, start it with an extra `--env-file` that sets
`REVIEW_ROOT` to that folder and `AI_REVIEW=on`.

## Conventions that are load-bearing

- **No false "pass".** A checklist item may report `pass` only if a detector
  actually ran. No detector, or one that could not run (`not-applicable`), hands
  the item back to the user. There is a test for this. The one exception to
  "hands back" is `absent: true` on a not-applicable outcome, shown as
  "Doesn't apply" (status `does-not-apply`, never a pass, out of every count):
  only when the thing checked is clearly not in the project. Where it could
  exist out of the check's sight (unknown framework, unusual address, a
  library the check does not know), do not set `absent`. Files the reader
  skips (types not in `READABLE` in `server/src/files.ts`, too large, over
  the limit) are out of sight too: `snapshot.unread`/`incomplete` and
  `outOfSight()` in `review/project-files.ts` block the checklist
  questions' `absent`, and the password, upload and scripts ones, while any
  of them could hold the evidence. Older absents (session expiry, CSRF,
  Supabase, Dockerfile) do not consult it yet.
- **Your checklist (2026-10-25).** An item with no detector, or a
  not-applicable outcome marked `general: true`, has status `checklist`:
  a good-practice question, counted in `summary.checklist`, apart from
  `awaitingReview`, never a pass, and not holding a module back from
  "clear". "Needs your check" is only about this code: leads, and checks
  that could not run here. A question with no detector is marked absent
  only through `applicability` in `review/checks.ts` (passwords, accounts),
  which runs after the project checks and never overrides them. The
  private-network and build-steps questions are never skipped: no list of
  ways to send a request is complete, and hosting services build sites
  with no file in the repository.
- **Only proof is a risk.** Anything styled as a risk must be traced or be the
  problem itself. Unproven pattern hits are leads (`unproven`), never risks.
- **No warnings on correct code.** Several fixed bugs were warnings about code
  that was already right (a key in an ignored `.env`; `spawnSync` with an
  argument array). These teach users to ignore the tool. Treat one as a defect.
- **Precision over coverage.** Missing a real path is a gap; inventing one is a
  defect. When in doubt, return `undecidable`, never `valid` and never "safe".
- **Text about code is not code (2026-10-25).** A pattern that looks for a
  danger runs on `codeOnly(file)` (`analysis/ast.ts`): comments, quoted
  text holding a space, and regular-expression patterns are blanked, single-word strings (package names,
  `'md5'`, header names) are kept. Use `codeHits` in `rules/auth.ts` and
  `anyCodeMatch`/`codeLineOf` in `review/checks.ts`. A pattern that looks for
  a protection has three answers (`protectionShown`, 2026-11-10): in real
  code the item passes; only mentioned in a comment or a sentence (`// TODO:
  add helmet`, a commented-out `app.use(csrf())`) the item goes back to the
  user, where it used to pass; nowhere is the risk it always was. So a
  mention never passes an item and never turns into a new alarm. Applies to
  protective headers, rate limits, password scrambling, sign-in expiry,
  CSRF, webhook signatures, leaving passwords out of user records, and
  Express's error handler. Three protections are real inside quoted text
  and are read with `withoutComments` in their exact shape only: `;
  SameSite=Lax` as part of a cookie header, a `<meta http-equiv>` policy
  tag, and Mongoose's `.select("-password ...")`. Code that answers 429
  ("too many requests") with no limiter the check knows hands the
  rate-limit item back: a home-made limit does that, and so does relaying
  another service's answer. Three older faults in the same checks were
  fixed with it: a rate-limit word inside a header's name or a piece of
  text (`"x-ratelimit-remaining"`, `"rate_limit"`) passed the item with no
  limit; `csrf()` and `csrf({...})` were never recognised (the pattern
  only matched `csrf(name`), so an app protected that way was reported;
  and logging a count of AI tokens (`usage.input_tokens`, `maxTokens`) was
  reported as logging a secret (`TOKEN_COUNT`; a bare `token` or `tokens`
  still counts). Found by reviewing ShipBrace itself:
  its advice strings, `bench/cases.ts` sample apps and a test's Supabase
  example gave 11 false alarms. A query whose pasted pieces are all fixed
  text (`?` per item, a fixed `const`, `$${i + 1}`) is safe
  (`analysis/fixed-text.ts`); a name bound twice, a `let`, or anything
  else is not.
- **Redact at the boundary.** Excerpts pass through `redact()` before a finding
  exists, so a reported secret is never copied into logs or the UI.
- **Report text for people who do not read code (2026-10-23).** Every
  explanation (what, why, fix, reasons, questions) is at most three sentences
  (`test/wording.test.ts`), names pages ("the page /x", "the action /x"),
  not GET/POST or files, and keeps code out of `fix`: the code-level step goes
  in `fixDetail` (`Fix.detail`, `checkDetail`), shown as "Exact fix (paste
  into your AI assistant)". Repo-derived text is passed through `cleanText`
  (no invisible characters or line breaks, capped) because it is copied into
  AI assistants. Risks that can be right as they are (open pages, ownership)
  carry `mayBeIntended`; the dashboard's "This is intended" mark is per
  browser, keyed by risk id plus its text, and never changes the GitHub check
  or saved counts.
- **Plain language in user-facing text.** Tests forbid the words taint, sink,
  sanitiz*, CWE, and payload in risk explanations (`test/plain-words.ts`).
  A name from the reviewed code shown in code style (`` `sanitizeInput` ``)
  is exempt, since the report must name the function so it can be found;
  ShipBrace's own sentences are not.
- **Pin exact versions** in generated apps. Verify package versions against the
  registry rather than from memory.

## Current state and known gaps

- **Benchmark (94 apps, 46 real problems, 49 safe decoys), 2026-10-27:** rules
  alone prove 37; a perfect suggester proves 40; 43 of 49 safe cleared; 6
  false alarms, all known (`KNOWN_FALSE_ALARMS` in `test/bench.test.ts`, by
  case and marker; any other one fails the tests, and a fixed one must come
  off the list). The 12 "home-made cleaners" cases added that day show the
  sanitizer gap: sanitizers are recognised by name and only when assigned
  (`const safe = escapeX(v)`), so 5 broken cleaners with good names are
  missed (4 as "worth a look", 1 silent) and 6 correct ones with plain
  names, or called inside the dangerous line, are proven risks. The 37 and
  40 include `homemade-escape-sql-inline`, proven only because inline calls
  are not seen as cleaners: recognising inline calls by name alone would
  drop each score by one, which is expected, not a regression.
  `Number.parseInt`/`Number.parseFloat` now count like `parseInt` (case
  `number-parse-int-direct`). Before them (2026-10-20): 36/40, 39/40, 0 false alarms; the only
  other perfect-suggester miss is a React component pasting a `body` prop
  as raw HTML (stays "worth a look").

The rest of the current state is in two files that Claude Code loads when
matching files are opened: `.claude/rules/checker.md` (`packages/`,
`scripts/`: what each check finds and misses, the cleaner step, the
practice apps) and `.claude/rules/service.md` (`cloud/`, `server/`,
`app/`, `deploy/`, `Dockerfile`: hosting, limits, audits, the dashboard).
Open them directly to answer a question without touching code.

## Claude Code setup for this project (2026-10-18)

- **Hooks** (`.claude/settings.json`, scripts in `.claude/hooks/`):
  `protect-secrets.sh` blocks Read/Edit/Write of `.env`, `.env.*`,
  `.dev.vars*` and `*.pem` (not `*.example`); `lint-edited.sh` runs
  `oxlint --deny-warnings` on each edited `.ts/.tsx/.js/.mjs` file and hands
  problems back. Shell commands are not covered by the secret hook; the rule
  "never print secret values" still applies there.
- **Skill** `/ship` (`.claude/skills/ship/`): user-only. Checks a clean,
  pushed tree, runs typecheck, lint, tests and the benchmark, applies pending
  D1 migrations, deploys, then checks the live site (health, sign-in, CSP,
  robots, unsigned webhook refused, no folder review).
- **Sub-agent** `security-auditor` (`.claude/agents/`, added 2026-10-18):
  a read-only (Read, Grep, Glob) audit of ShipBrace itself, adapted from
  Osmani's agent-skills (MIT) with ShipBrace's own risky areas: webhook,
  sign-in, hostile repositories, the reviewer's internet wall, D1. It skips
  the benchmark's deliberately vulnerable apps. Its findings are leads that
  the main session verifies. It cannot run `npm audit`, so the main session
  does. First run 2026-10-18.
  **Rule since 2026-10-21:** every change to ShipBrace's own service
  (`cloud/`, `server/`, `app/`, `deploy/`, `Dockerfile`) gets a
  `security-auditor` pass scoped to the changed files before it is
  committed, and a full audit runs before opening up to other users.
  Checker changes (`packages/guardrails`) get `conventions-reviewer`
  instead. In a session opened from the parent folder, project agents do not
  load: give a general-purpose agent the agent file to follow.
- **Sub-agent** `conventions-reviewer` (`.claude/agents/`, added 2026-10-20):
  checks a finished change against the load-bearing conventions above and
  runs typecheck, lint, tests and the benchmark (never with `--model`). It
  reads and runs checks only; use it before committing checker changes.
- **Planned:** the Cloudflare Observability MCP server, when live debugging
  is needed.

**Outside tools** were evaluated on 2026-10-18; the verdicts and reasons
are in `docs/claude-code-tools.md`. Two still apply: run Fallow only on
demand as `npx fallow@3.34.1` and never use its auto-fix (it lists
`Reviewer.claim`, which enforces "each outside step once", as unused); and
read any skill from outside the Anthropic Directory before installing it.

## Roadmap

### Next steps (where work stopped, 2026-11-11)

Read this first in a new session, then CLAUDE.local.md ("Waiting on Murat")
for the private items. Do not start any of these unasked: summarise them,
recommend one, and wait for Murat's choice.

**State:** everything is pushed and deployed (2026-11-11): last deployed
commit `97fbf54`, live version `40ddc80d`, all six live checks passed. The
audit fixes and the set-aside work are live, migration 0008 is applied, and
the year-long asset caching is taken out again. Murat signed in after the
deploy with the invite list by account number (audit log, 2026-11-12), and
accepted the new notices. 431 tests.

1. **The AI cleaner step: live since 2026-11-11, not yet seen running**
   (Murat's decisions, 2026-11-10: Haiku 5.5 for his reviews only, neutral
   mark when softened, ping sample changed). What it is and how it is
   wired: "The one rule" above and "Cleaner step built for going live" in
   `.claude/rules/checker.md`. Still to see:
   - Murat is shown the notices once more (`NOTICE_VERSION` changed) and
     the AI switch's new description;
   - the first review of an app with a home-made cleaner is the step's
     first true end-to-end run on Cloudflare: read the Worker log line
     "cleaner check (...)" for the real token counts, and check the report
     (a labelled finding or a "worth a look" note, the footer sentence, and
     a neutral check when softened);
   - `AI_CLEANER_CHECK` set to "off" in `cloud/wrangler.jsonc` and a deploy
     turns just this step off.
   Not followed, on purpose (each leaves the rules' answer in place):
   CommonJS `require`, values passed through a second name, re-tracing
   across files. Opening the step to anyone else waits for the opening-up
   decisions (privacy policy, the provider's data agreement).
2. **Smaller checker improvements: done 2026-11-10, live since
   2026-11-11** (`protectionShown` in the conventions above; the
   password-hashes item, session set-up and redirect-only pages in
   `.claude/rules/checker.md`).
   **Offered, not started:**
   - bringing the unused Docker setup in `deploy/` in line with Cloudflare
     (limits, records, who may use the AI step) before anyone uses it;
   - requiring CI to pass before changes land on `master`: a GitHub
     setting Murat switches on; walk him through it when he asks;
   - a function written inline in `app.use(...)`, and names the checker
     does not know, still count as a sign-in check for every route;
   - a map of the checker per OWASP category (detects / misses / effort);
   - scoring NodeGoat and Juice Shop against their documented holes, like
     DVNA;
   - testing whether the reports' suggested fixes really fix things
     (Murat's idea, 2026-10-25): apply each to the practice apps and the
     benchmark, re-run, check the problem is gone and nothing broke. Its
     own project of several days, to be planned first;
   - a `.claude/claude-security-guidance.md` note telling the
     security-guidance plugin that `packages/guardrails/bench/` and test
     samples are deliberately vulnerable.
3. **Opening up** (needs Murat's product decisions): see "Before anyone else
   uses it" below.

Done: review history (2026-10-09), the sealed reviewer (2026-10-09), hosting
on Cloudflare (2026-10-10), sign-in with GitHub, paste-a-link, notices and
per-installation switches (2026-10-10), the name ShipBrace, a public
repository with CI and a README screenshot, a dead-code cleanup, and the
Claude Code setup above (2026-10-18).

**The smarter checker (agreed 2026-10-18, widened and built 2026-10-20),**
roadmap item 6 below. Steps 1-5 are done, tried on the practice apps (see
`.claude/rules/checker.md`) and deployed (2026-10-21).
Every new check gets benchmark cases (a real problem and a safe look-alike),
adds no false alarm beyond the known list in `test/bench.test.ts`, is tried on the practice apps, and fills a checklist
item only once it can actually run ("no false pass"). In order:

1. **Groundwork (done 2026-10-20).** `conventions-reviewer` added; legacy
   regex inventory and matcher removed.
2. **The agreed gaps.** Done 2026-10-20: stored attacks; matching each
   sanitizer to the kinds of operation it protects; not flagging routes that
   only return constants; sign-in checks written inside a handler;
   transactions written `` tx`...` ``; SQL-looking text in documentation
   templates; XXE.
3. **New proven checks** (done 2026-10-20) (input traced to the problem, so they are risks):
   mass assignment (a request body saved whole, e.g. `User.create(req.body)`,
   so a visitor can set `role` or `owner_id`); unsafe decoding of input
   (extend the existing `unserialize` detection to unsafe YAML loading and
   similar, and give `integrity/untrusted-deserialization` its detector);
   webhooks acted on without checking their signature.
4. **New project checks** (done 2026-10-20; read from files, no tracing): secret keys in code
   that runs in the browser (`NEXT_PUBLIC_`/`VITE_` names holding secrets, a
   Supabase service-role key in client code); Supabase tables without row
   level security and public storage buckets, from SQL migrations; session
   cookies missing `HttpOnly`/`Secure`/`SameSite`; debug mode left on in
   production settings; a Dockerfile that runs as root; uploads with no size
   limit; packages nothing imports, names one typo away from a popular
   package (fixed list in the code, no network), and packages with install
   scripts (from the lockfile).
5. **Leads only ("worth a look", never risks; done 2026-10-20):** AI features where visitor
   input reaches a model prompt and the model's answer reaches a database,
   command or tool (prompt injection); routes that send whole tables back
   without a limit.

Not in this plan (each needs a product decision first): checking a user's
live site (exposed files, headers, speed, search-engine basics; the
reviewer's internet is off on purpose), secrets in git history (reviews get
a snapshot without history), and branch protection (needs a wider GitHub
App permission).

### Before anyone else uses it

1. **Legal:** a privacy policy built from docs/legal/third-party-services.md
   section 5, reviewed by a lawyer; the AI provider's data processing
   agreement; a trademark check on "ShipBrace".
2. **Opening up:** make the GitHub App public, widen `ALLOWED_GITHUB_IDS`,
   raise `DAILY_REVIEW_LIMIT` (wrangler.jsonc), and decide who may use the AI
   step (`AI_ALLOWED_GITHUB_IDS`; the only part with a per-review cost) --
   later through a subscription and free trial.
3. **Small gaps:** "your call" ticks are per browser, shared across every
   repository; they should be per repository.

### The rest of the vision

4. **Deployment:** putting users' apps online with Cloudflare -- the
   "handles deployment" part. Not started. Open question: the user's own
   Cloudflare account, or ShipBrace's.
5. **Starting structure for new apps:** `packages/scaffold` exists and passes
   its own review, but nothing lets a user reach it yet.
6. **More detection:** browser-side code.

See `docs/architecture.md` for the reasoning behind these decisions.
