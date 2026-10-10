# Aegis

A hosted platform that sits beside whatever LLM a developer uses to build a web
app, and handles security, architecture, and deployment so they can stay in the
design surface. An opt-in detailed mode lets them follow along in the code.

The user (product owner) is not a developer. Explain decisions in plain
language, lead with a recommendation, and surface product choices to them;
absorb engineering choices yourself.

## Working with the product owner (Murat)

- Start every reply with "Murat".
- Plain language, define terms on first use, lead with one recommendation
  rather than a menu. Engineering choices are yours; product choices are his.
- Build the design he specifies. If an implementation choice would change how
  it works, say so *before* building, not after measuring.
- He asked for honest numbers: report misses and false alarms as plainly as
  wins, and verify claims (versions, results) rather than recalling them.

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
| `server/` | Review API (`GET`/`POST /api/review`), GitHub webhook, kept reviews (`/api/reviews/:id`, `/api/history/:id`); serves `app/dist` when built |
| `server/src/sandbox/` | **Every review runs here**, in a sealed child process: no secrets, no network, reads limited to Aegis's code, time and memory limits |
| `server/src/history.ts` | Review history in PostgreSQL: schema migrations, save, read back by unguessable link |
| `app/` | React dashboard: the live review at `/`, a kept review at `/reviews/:id`, a repository's history at `/history/:id` |
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

Development moved to a Mac on 2026-10-09 (Bun installed, Docker not). Aegis
itself still runs on Node; the Bun-based root scripts are untested. Node works
everywhere:

```bash
# PostgreSQL 18 (Homebrew, not started at login). Databases: aegis, aegis_test.
LC_ALL=en_US.UTF-8 /opt/homebrew/opt/postgresql@18/bin/pg_ctl -D /opt/homebrew/var/postgresql@18 -l /opt/homebrew/var/log/postgresql@18.log start

# all tests (expect 170 pass). Without TEST_DATABASE_URL the 6 database tests
# are skipped and say so; it must name a database ending in _test (it is wiped).
TEST_DATABASE_URL=postgres:///aegis_test node --experimental-strip-types --test packages/guardrails/test/*.test.ts packages/scaffold/test/*.test.ts server/test/*.test.ts

# review API on :3000. Set REVIEW_ROOT explicitly: npm runs workspace scripts
# from inside server/, so without it only that one folder is reviewed.
# PACKAGE_LOOKUP=off keeps it fully offline (no OSV.dev lookups).
# Build the dashboard first so the server serves it (links from GitHub checks).
npm run build --workspace @aegis/app
REVIEW_ROOT="$PWD" node --experimental-strip-types --env-file=.env server/src/index.ts

# dashboard on :5173 (falls back to app/src/fixtures/review.json without the API)
npm run dev --workspace @aegis/app

# benchmark scores (add --model, with --env-file=.env, to include Claude; costs credit)
node --experimental-strip-types scripts/bench.ts

# compare review with and without a model (costs API credit)
node --experimental-strip-types --env-file=.env scripts/simulate.ts <folder>
```

`.env` holds `ANTHROPIC_API_KEY`, the GitHub App settings (`GITHUB_APP_ID`,
`GITHUB_PRIVATE_KEY_PATH`, `GITHUB_WEBHOOK_SECRET`), `DATABASE_URL`
(`postgres:///aegis` here; no password over the local socket) and, while a
tunnel is open, `PUBLIC_URL` (its address, for links in checks); the App's key file is
`github-app.pem`. All are git-ignored and must stay that way: on a new machine
they are recreated, never copied through chat or GitHub. Never print their
values. `GITHUB_PRIVATE_KEY_PATH` must be absolute: the server resolves it from
wherever it starts, which is `server/` under `npm start --workspace`. Prepaid
credits with auto-reload off, so it cannot overspend.

The practice apps used for outside validation are not in this repository;
re-clone them read-only (never install or run them) into `~/aegis-test-repos`:
appsecco/dvna, OWASP/NodeGoat, juice-shop/juice-shop. The `review-api-dvna-ai`
launch entry expects `~/aegis-test-repos/dvna.env` there.

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

- **Benchmark (56 apps, 31 real problems, 26 safe decoys), 2026-10-01:** rules
  alone prove 27; a perfect suggester proves 30; zero false alarms. Only
  miss: a stored comment rendered as raw HTML. The starter kit is held to its
  own review (`packages/scaffold/test/self-review.test.ts`): no warnings
  except the lockfile a fresh app gets on first install.
- **"Checked" says what was checked** (`ActionItem.covers`). Error pages hand
  back to the user when Express's built-in error page is in use (it leaks
  unless NODE_ENV=production); Sequelize query logging, session secrets in
  code, and missing CSRF protection on cookie sign-in (new item
  `access-control/csrf`) are detected. MongoDB-style filters taking request
  values inline, and `$where` built from values, are `nosql` operations.
- **The whole stack is in every generated app** (2026-10-01,
  `packages/scaffold/src/modules/stack.ts`): Chart.js + react-chartjs-2
  (`components/charts.tsx`), SheetJS from its CDN (`lib/spreadsheet.ts`,
  size-limited reads, formula-injection-safe exports), and both `postgres` and
  `mysql2` (`server/src/mysql.ts`, tagged-template only, optional `MYSQL_URL`).
  The old `charts`/`spreadsheets` features and `database: "mysql"` silently
  did nothing and were removed. The pin check now covers devDependencies and
  `latest`; Aegis's own manifests are pinned. The dashboard has "Download as
  Excel" (lazy-loaded, cells made plain text). Newer versions than the spec
  (TypeScript 7, Vite 8 stable, Bun 1.4) were approved by the user.
- **Aegis itself still runs on Node, not Bun** (Bun is not installed here), and
  has no PostgreSQL, Docker, or login yet: those come with hosting.
- **Admin pages and password hashes** (project checks): a route with
  `admin` in its address needs a role-ish guard or an `if` testing the role
  (showing the role in a page does not count); a route that loads user
  records (`User.find*`) and sends them whole is reported when the project
  has a password field and no sign of removing it anywhere. DVNA: both found.
- **Page templates** (EJS, Handlebars, Pug, Nunjucks/Swig): `res.render(view,
  locals)` is an html operation only for the values the template prints raw
  (`<%-`, `{{{`, `!{`, `| safe`, autoescape off). Plain reassignments
  (`x = ...`) are followed. `res.send` of a template containing a tag is html.
- **Outside validation (2026-10-01), practice apps cloned read-only into
  `aegis-test-repos` (DVNA, OWASP NodeGoat, OWASP Juice
  Shop):** testing on Express code found false alarms the benchmark never
  covered -- per-route middleware and `app.post(path, security.isAuthorized())`
  were not seen as sign-in checks (DVNA 27 -> 1 open-route warnings, Juice Shop
  86 -> 18). DVNA: 5 of its 19 documented holes found automatically (SQL and
  command injection, insecure deserialisation, open redirect, missing headers).
  Templates added afterwards (DVNA reflected XSS now caught). Not detected yet: XXE, NoSQL injection,
  CSRF, a session secret left at a default, and sign-in checks written inside
  a handler (Juice Shop `dataErasure`, 2 remaining false alarms).
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
- **GitHub App works end to end (first live run 2026-10-01):** App ID 5157570
  ("yg-aegis-review"), installed only on the private test repo
  yalinGenc704/aegis-dvna-test (a DVNA copy). A push produced a failing check
  with 12 line notes. Local setup: `GITHUB_*` settings in `.env`, key in
  `github-app.pem` (git-ignored), and a temporary Cloudflare quick tunnel
  (`cloudflared tunnel --url http://localhost:3000`). The tunnel address
  changes every run, so the App's webhook URL must be updated each time until
  it is hosted.
- **Review history (2026-10-09).** With `DATABASE_URL`, each reviewed push is
  kept (full result, commit, time) and the check links to it (`details_url`
  plus two links atop the summary; needs `PUBLIC_URL`). No sign-in yet: pages
  are reached by unguessable 144-bit links only the check shows. If saving
  fails the check is still posted in full, without links. Nothing is deleted
  yet; retention and deletion on uninstall are in the legal checklist. First
  live run 2026-10-09 (this Mac, new App key): a push to aegis-dvna-test was
  saved and posted as a failing check (6 high, 9 medium, 2 low), with links
  that opened through the tunnel. Quick tunnels can drop ("Tunnel not
  found"); restart it, update PUBLIC_URL and the webhook URL, and use
  Redeliver under the App's Advanced page rather than pushing again.
- **Every review is sealed off (2026-10-09)** in a child process
  (`server/src/sandbox/`, details in docs/architecture.md): empty environment,
  Node permission model (reads only Aegis's code; no network, writes or child
  processes), 60 s work limit excluding AI waits, 1 GB JS memory, two at once.
  Identical results on all 56 benchmark apps; ~75 ms extra per review. It is a
  JavaScript-level wall: the full seal is a locked-down container at hosting.
- **The query check trusts tagged templates by name** (`SAFE_TAG`: `sql`, `db`,
  `query`). postgres.js transactions are usually written `` tx`...` ``, which
  gets a false "worth a look"; `history.ts` names its transaction `sql` to
  avoid it. Users' apps would hit this (step 8).

## Next steps (agreed with Murat 2026-10-01; 1 and 3 done 2026-10-09)

**At the start of a session, do not begin these on your own.** Summarise where
things stand, present this list in plain language (grouped as below, with
time estimates and the decisions each needs), give the recommendation, and
ask Murat which to start. Wait for his answer.

**Recommended next: 2**, once Murat has chosen where it runs and a domain.
Proposed 2026-10-09, not yet agreed.

### Making it usable without the laptop

1. ~~**Store past reviews in PostgreSQL.**~~ Done 2026-10-09.
2. **Put Aegis online, running all the time.** ~1-2 sessions. Needs two
   decisions from Murat:
   - *Where it runs.* Recommendation: a small rented server (VPS) running
     Docker, with Cloudflare Tunnel in front -- exactly the stack's setup.
     Typically around $5/month.
   - *A domain name* added to Cloudflare, so the tunnel has a permanent
     address and the GitHub App's webhook URL never changes again. Typically
     around $10/year.
   - Also needed: the container is the full seal for step 3 (no outbound
     network for the review process, read-only filesystem, memory cap,
     non-root user), PostgreSQL in Docker, and `PUBLIC_URL` set to the domain.

### Required before anyone else uses it

3. ~~**Run the code reader sealed off.**~~ Done 2026-10-09 (the container
   seal remains, under step 2).
4. **Sign-up, the legal notices, and per-person on/off switches** for the AI
   and the package lookup (docs/legal/third-party-services.md section 4).
   ~1-2 sessions. Also: put kept reviews behind sign-in, decide how long they
   are kept, and make the "your call" ticks per repository (today they are
   per browser, shared across every repository).
5. **A real product name.** "Aegis" is crowded (several security tools for
   AI-built apps use it); choose one and have it trademark-checked.

### The rest of the original vision

6. **Switch Aegis itself to Bun and Docker** (the generated apps already use
   them). Done for the starter kit on 2026-10-01: charts, Excel, and MySQL.
7. **Deployment:** putting users' apps online with Cloudflare -- the "handles
   deployment" part of the vision. Not started.
8. **More detection:** stored attacks (bad data saved, shown later),
   browser-side code, the XML upload attack (XXE), and sign-in checks written
   inside a handler (Juice Shop `dataErasure`), and transactions written
   `` tx`...` `` (see above). Also remove or deprecate the legacy exports listed
   above.

See `docs/architecture.md` for the reasoning behind these decisions.
