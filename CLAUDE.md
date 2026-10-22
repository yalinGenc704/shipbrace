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
| `server/src/sandbox/` | **Every review runs here**, in a sealed child process: no secrets, no network, reads limited to ShipBrace's code, time and memory limits |
| `cloud/` | **Where it runs: Cloudflare, live at https://app.shipbrace.com.** Worker (`src/index.ts`: webhook, queue job, kept-review API, dashboard assets), one review in a container (`src/review-container.ts`), daily limits counted at each start (`src/limits.ts`), reviewer container class with internet off (`src/reviewer.ts`), D1 history (`src/history-d1.ts`, `migrations/`), `wrangler.jsonc`. `wall-check/` re-proves the internet wall |
| `Dockerfile`, `deploy/` | **Hosting.** One image, two roles (server, reviewer); `deploy/compose.yaml` runs shipbrace, reviewer, postgres, backup, cloudflared; `deploy/README.md` is the server setup guide |
| `server/src/history.ts` | Review history in PostgreSQL: schema migrations, save, read back by unguessable link |
| `app/` | React dashboard: the live review at `/`, a kept review at `/reviews/:id`, a repository's history at `/history/:id` |
| `scripts/simulate.ts` | Reviews a folder with and without a model and reports the difference |
| `packages/guardrails/bench/` | **The benchmark.** Sample apps with a known answer key (`cases.ts`) and the grader (`grade.ts`). `test/bench.test.ts` ratchets the scores |
| `packages/guardrails/src/review/vulnerabilities.ts` | Known flaws in installed packages via OSV.dev (A03). Off unless a `VulnerabilitySource` is passed; the server passes one |
| `docs/legal/third-party-services.md` | What leaves the platform, what users must be told, draft privacy-policy text |
| `README.md` | Plain-language overview for anyone: the vision, how a review decides, the rules, honest numbers, what is built |
| `scripts/bench.ts` | Prints the benchmark scores: rules alone, perfect suggester, optionally a real model |

### Removed legacy (2026-10-20)

The old regex inventory (`buildInventory`, `findDoors`, `findAssignments`...)
and the old matcher (`confirmProposal`, `confirmAll`) are gone: the regex
version read code inside string literals as real code, and the matcher could
never let a proposal contribute. `analysis/inventory.ts` now holds only the
shared types; build an inventory with `buildInventoryFromAst` and decide
claims with `verifyClaim`.

## Running things

Development moved to a Mac on 2026-10-09 (Bun installed, Docker not). ShipBrace
itself still runs on Node; the Bun-based root scripts are untested. Node works
everywhere:

```bash
# PostgreSQL 18 (Homebrew, not started at login). Databases: shipbrace, shipbrace_test.
LC_ALL=en_US.UTF-8 /opt/homebrew/opt/postgresql@18/bin/pg_ctl -D /opt/homebrew/var/postgresql@18 -l /opt/homebrew/var/log/postgresql@18.log start

# all tests (expect 290 pass). Without TEST_DATABASE_URL the 6 database tests
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

- **Benchmark (81 apps, 40 real problems, 42 safe decoys), 2026-10-20:** rules
  alone prove 36; a perfect suggester proves 39; zero false alarms. Only
  miss: a React component pasting a `body` prop as raw HTML, with nothing
  showing where the prop comes from (stays "worth a look").
- **Stored attacks (2026-10-20).** A table column a visitor's unchecked
  value is saved into (SQL `INSERT ... VALUES`/`UPDATE ... SET`, model
  `create`/`update` data; never `WHERE` or a filter) makes reads of it a
  `stored-data` input, followed like any other. A read counts only when
  everything it returns that could be text is visitor-written (ids and
  timestamps aside); a read mixing in app-written columns stays silent,
  because the result is followed as one value. Stored data is left out of
  ownership claims.
- **Checks count only against what they protect (2026-10-20,
  `Sanitizer.protects`, `checksFor`).** Read from the name: HTML escaping and
  DOMPurify protect pages; SQL escaping queries; `shell`-named steps and
  shell-quote's `quote` (only when imported from it) commands; `basename`,
  `normalize`, `resolve` file paths; `escapeRegExp` nothing. Numbers, schema
  checks, allowlists and names that do not say (`sanitizeInput`) count
  everywhere. Applied in `analyseTaint` and `verifyClaim`.
- **Fixed-answer routes are not "unlocked" (2026-10-20,
  `Door.answersOnlyFixed`).** An inline handler with no middleware whose code
  only calls answer methods on its own parameters (`c.notFound()`,
  `res.status(404).send("No")`) has nothing to protect.
- **Sign-in checked inside the handler (2026-10-20, `signInCheckedFirst`).**
  A route counts as guarded when its inline handler's first real step reads
  who is signed in (`c.get("user")`, `req.user`, `getServerSession(c)`,
  `authenticatedUsers.get(token)`) and an `if (!x)` / `x == null` branch
  returns or throws. Only declarations may come before it; a lookup fed by
  route, query or body values (`getAuthor(id)`) is never a sign-in check.
- **Transactions and documentation (2026-10-20).** A tag that is the
  parameter of a function passed to `sql.begin`/`transaction`/`savepoint`/
  `reserve` is parameterised like `sql` (`tx.unsafe(...)` is not). A
  template or `+` counts as a query only when its text starts with a
  statement keyword (after any leading SQL comments), so prose mentioning a
  query is not one.
- **XML outside references (XXE, 2026-10-20).** A libxmljs
  `parseXml`/`parseXmlString`/`parseXmlAsync` call whose options object
  literally sets `noent` or `dtdload` is an `xml-entities` operation
  (checklist item `injection/xml-entities`, whose "checked" text names
  libxmljs only; a project depending on libxml2-wasm, libxslt, libxml-xsd
  or xmllint gets the item handed back). Not covered: options held in a variable, libxslt,
  libxml-xsd, xmllint. xml2js, fast-xml-parser, xmldom and sax never fetch
  outside files.
- **Mass assignment (2026-10-20, `analysis/schemas.ts`,
  `addMassAssignment`).** Table fields are read from Prisma, SQL `CREATE
  TABLE`, Mongoose, Sequelize and Drizzle definitions (reviews now read
  `.prisma` files; they are never sent to the AI step). A model write that
  saves the visitor's whole request untouched (`req.body`, `await
  c.req.json()`, or plain copies of it, or a spread of it) into a table with a
  sensitive field (role, admin flag, balance, plan, owner/user id...) that is
  not set after the spread is a `mass-assignment` operation, item
  `access-control/mass-assignment`. Silent when: the table's fields are
  unknown; the request passes through any call, rebuild or destructuring; a
  check or trim of it (`parse`, `validate*`, `pick`, `delete x.role`...)
  comes first in the handler; any code replaces `req.body`; the route is
  guarded by an admin check. With no table definitions at all, the item is
  handed back as not checked.
- **Unsafe decoding (2026-10-20).** node-serialize `unserialize` (only when
  imported from node-serialize), js-yaml `unsafeLoad`, funcster
  `deepDeserialize`, and js-yaml `load`/`loadAll` with a `...FULL_SCHEMA`
  option are `unsafe-decoding` operations, item `integrity/unsafe-decoding`
  (the broader `integrity/untrusted-deserialization` keeps no detector so it
  cannot pass falsely). js-yaml 3's plain `load` is unsafe but not told
  apart from version 4's, so it is missed.
- **Webhook signatures (2026-10-20, project check
  `webhooks:signature-checked`, item `integrity/webhook-signatures`).** POST
  routes under `/webhook(s)` or `/hook(s)` that read the body. Pass when each
  route's own file shows a signature check (Stripe `constructEvent`, HMAC +
  `timingSafeEqual`, a webhook library's verify/validate, a signature header);
  a risk only when nothing in the project checks signatures or a shared-secret
  header; otherwise handed back. A bare `.verify(` (such as `jwt.verify`)
  does not count.
- **Project file checks (2026-10-20, `review/project-files.ts`).** Supabase
  tables (from SQL migrations, comments and `$$` bodies ignored) without
  row level security (`access-control/database-rules`; public buckets are a
  notice); the final Dockerfile stage running as root, following `FROM
  <stage>` (`config/container-user`); `NODE_ENV=development`/`DEBUG` in the
  final Dockerfile stage or a compose file not named dev/local/test/override
  (`config/debug-off`); multer without `limits` (`design/upload-limits`);
  packages one edit from ~100 popular names, handed back rather than called
  risks, with install scripts and unused dependencies as a notice
  (`components/suspicious-packages`). Rules: secrets behind `NEXT_PUBLIC_`/
  `REACT_APP_`/`EXPO_PUBLIC_`/`NUXT_PUBLIC_`/`PUBLIC_` as well as `VITE_`
  (keys public by design such as Firebase, Maps, reCAPTCHA, PostHog are
  skipped), and Supabase's service-role key in plainly browser code
  (`"use client"`, `client|frontend|web/src/`, `src/components|hooks/`);
  `auth/cookie-readable-by-scripts`: `res.cookie`/`reply.setCookie`/Hono
  `setCookie` of a login cookie without `httpOnly` (not csrf/xsrf cookies,
  clearing on sign-out, spread options, SvelteKit or Koa). Missing `Secure`
  is not reported.
- **Two lead-only rules (2026-10-20, `rules/leads.ts`, in
  `UNPROVEN_RULES`).** `ai/prompt-to-action` (item
  `injection/ai-instructions`): within one function, visitor input is read,
  an Anthropic/OpenAI/Gemini/Vercel AI SDK/LangChain model is called, and its
  answer goes to a query, command, `fetch`, delete, file write, redirect or
  email, or the model is given tools; showing or saving the answer is not
  flagged; with no known AI library in package.json the item is handed back.
  `design/unbounded-list` (item `design/unbounded-lists`): a route sends back
  a model read with no filter or a plain-text SQL `SELECT` with no
  WHERE/LIMIT; admin-guarded routes are skipped. Both items' "checked" text
  names exactly what was covered. The starter kit is held to its
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
  `latest`; ShipBrace's own manifests are pinned. The dashboard has "Download as
  Excel" (lazy-loaded, cells made plain text). Newer versions than the spec
  (TypeScript 7, Vite 8 stable, Bun 1.4) were approved by the user.
- **ShipBrace itself still runs on Node, not Bun** (Bun is not installed here), and
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
  `shipbrace-test-repos` (DVNA, OWASP NodeGoat, OWASP Juice
  Shop):** testing on Express code found false alarms the benchmark never
  covered -- per-route middleware and `app.post(path, security.isAuthorized())`
  were not seen as sign-in checks (DVNA 27 -> 1 open-route warnings, Juice Shop
  86 -> 18). DVNA: 5 of its 19 documented holes found automatically (SQL and
  command injection, insecure deserialisation, open redirect, missing headers).
  Templates added afterwards (DVNA reflected XSS now caught). Not detected yet: NoSQL injection,
  CSRF, a session secret left at a default. Sign-in checks written inside a
  handler (Juice Shop `dataErasure`) are recognised since 2026-10-20.
- **Practice apps re-run with the smarter checker (2026-10-21; DVNA 9ba473a,
  NodeGoat c5cb68a, Juice Shop 399fba7).** Every new finding checked by hand
  and real: DVNA's XML upload hole (XXE), node-serialize now under unsafe
  decoding, DVNA's container running as root; Juice Shop's memories upload
  with no size limit, its `token` cookie readable by scripts (2 places), and
  leads on its chatbot (visitor text to a model with tools) and its full user
  list. Juice Shop's two `dataErasure` open-route false alarms are gone.
  Gaps: Juice Shop's XXE uses libxml2-wasm, which is not followed (the item
  now says so instead of passing); no stored attack or mass assignment was
  found in any of the three (NodeGoat's stored XSS goes through templates
  with autoescape off, not followed). Totals: DVNA 17 -> 19 risks, NodeGoat
  7 -> 7, Juice Shop 52 -> 53 risks and 5 -> 7 leads.
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
- 16 of 49 checklist items have no detector and are left to the user (counted 2026-10-20). The
  checklist follows OWASP Top 10:2025; the four items added for its new
  categories (A03 supply chain, A10 exceptional conditions) have no detector yet.
- **GitHub App works end to end (first live run 2026-10-01):** App ID 5157570
  ("yg-aegis-review"), installed only on the private test repo
  yalinGenc704/aegis-dvna-test (a DVNA copy). A push produced a failing check
  with 12 line notes. Local setup: `GITHUB_*` settings in `.env`, key in
  `github-app.pem` (git-ignored), and a temporary Cloudflare quick tunnel
  (`cloudflared tunnel --url http://localhost:3000`; start the server with
  `LOCAL_REVIEW=off` while a tunnel is open). The tunnel address
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
  Node permission model (reads only ShipBrace's code; no network, writes or child
  processes), 60 s work limit excluding AI waits, 1 GB JS memory, two at once.
  Identical results on all 56 benchmark apps; ~75 ms extra per review. It is a
  JavaScript-level wall: the full seal is a locked-down container at hosting.
- **Security pass on ShipBrace itself (2026-10-09).** Fixed: a reviewed folder's
  own `.git/config` could make `git ls-files` run its program via
  `core.fsmonitor` (confirmed, now overridden; test fails on the old code);
  no Content Security Policy (now strict, same-origin only); no way to turn
  off folder reviews (`LOCAL_REVIEW=off`, for hosting: removes `/api/review`
  and `/`); no size limit on `POST /api/review`; no cap on waiting reviews
  (`maxWaiting` 50, then refused as "busy"). Left for hosting: rate limiting
  in Cloudflare (behind the tunnel the server cannot see visitors' addresses).
- **ShipBrace reviews itself clean (2026-10-09):** 0 risks (was 2 high, 10
  medium, all false). The logging check now reads parsed code and judges the
  values passed to `console.*`, not words in the message. The key check skips
  obvious placeholders (`looksMadeUp`: placeholder words in one case, six
  repeated or consecutive characters); measured on 1M random realistic keys,
  about 1 in 100,000 is wrongly skipped. Test fixtures that must look real
  assemble their keys at runtime. The README sample in
  `scaffold/src/modules/base.ts` that mentions a SQL example is no longer read
  as a query (2026-10-20).
- **Live on Cloudflare since 2026-10-10** at https://app.shipbrace.com (chosen over a
  rented server). Workers Paid plan. A push: the
  Worker checks the signature and queues it; the queue job (no retries)
  fetches the code, reviews it in a fresh `standard-1` reviewer container
  (`enableInternet = false`; its only way out is `shipbrace.internal`,
  answered by the Worker at most once per step), posts the check, keeps the
  result in D1 (30-day time travel; rows over ~1.9 MB are not kept). First
  live push: same result as the Node server (6 high, 9 medium, 2 low).
  `wall-check/` proved on Cloudflare that web, raw-IP, socket and DNS
  attempts all fail while `shipbrace.internal` works; it was then deleted.
  The workers.dev address is off. Secrets are set with
  `wrangler secret put`; wrangler's login uses narrow scopes and the macOS
  Keychain. Deploy from `cloud/`: `npm run build --workspace @shipbrace/app`,
  then `npx wrangler deploy` (builds the reviewer for linux/amd64 through
  emulation; Colima must be running). For `wall-check/`, call
  `node_modules/.bin/wrangler` with `--config`: `npx` runs from `cloud/` and
  would deploy the main app instead. Local trial: `npx wrangler dev` with
  `cloud/.dev.vars` (git-ignored); local containers run with extra
  privileges, unlike Cloudflare.
- **The Docker setup in `deploy/` is the fallback** for an ordinary server
  (tested 2026-10-09, not in use). The reviewer runs in its own container with `network_mode: none`,
  talking to the server over a Unix socket (`sandbox/channel.ts`,
  `remote.ts`, `reviewer.ts`): V8 format towards the reviewer, size-capped
  JSON back, each outside step at most once, stop reasons from a fixed list.
  Verified with Colima: a review through every container; reviewer reaches
  neither internet nor database; database has no internet; read-only disks,
  uid 1000; no published ports; reviewer outage reported plainly; a backup
  restored. Backups stay on the server: off-server copies are undecided.
- **Self-review (2026-10-10):** no proven vulnerabilities. Reported: two
  catch-all routes that only answer 404 (the open-route check cannot yet tell
  a handler with nothing behind it from one that returns data), and three
  "worth a look" notes on D1 queries that build `?` placeholder lists. Fixed
  in the checker that day: a fetch whose *public* origin is fixed in the code
  is not request forgery (internal hosts still are), and `/webhook(s)`,
  `/callback`, `/oauth` routes are public by design.
- **Security audit of ShipBrace (2026-10-18, `security-auditor`).** `npm
  audit`: 0 known vulnerabilities. Fixed the same day: `redact()` now hides
  unquoted credential values in environment files, Stripe/GitHub/Google key
  shapes, connection-string passwords and private-key blocks, and the
  committed-`.env` finding shows the variable name only; every GitHub and
  OSV.dev request has a time limit (the Anthropic SDK has its own, 10
  minutes). Kept reviews now open only for the person who started them (who
  pushed, from the push's `sender`, or who pasted the link: `reviews.ran_by`,
  migration 0004) and the repository's admins, while GitHub still lets them
  read it (user decision 2026-10-18, all repositories, public ones
  included). Others with access see only their own reviews in a history;
  reviews kept before 0004 open for admins only. The Docker fallback stores
  nothing about who ran a review. **This repository is public: open findings are not written
  here.** They are kept in Claude's private memory for this project and
  listed when Murat asks what is left to fix.
- **Review limits, AI access and rate limiting (2026-10-21, user decisions).**
  Each GitHub account (installation) gets `MONTHLY_REVIEW_LIMIT` (50) reviews
  per calendar month (UTC, resets on the 1st), counting every push or pasted
  review of its repositories at start, and at most
  `ACCOUNT_DAILY_REVIEW_LIMIT` (10) in any 24 hours; `DAILY_REVIEW_LIMIT` (50,
  rolling 24 hours, across everyone) is a safety cap (`cloud/src/limits.ts`).
  The check says which limit stopped a review (`monthly-limit` /
  `account-daily-limit` / `limit`). The AI step
  runs only for reviews started by GitHub ids in `AI_ALLOWED_GITHUB_IDS`
  (the owner, 174497899) with that installation's switch on
  (`cloud/src/ai-access.ts`); `AI_REVIEW` is on only for that. Per-minute
  limits are exact, in a Durable Object per key (`cloud/src/rate-counter.ts`,
  sliding window in `rate-window.ts`): 60 requests per signed-in person on
  `/api/*`, 10 sign-in attempts (per address; IPv6 per /64) or pasted links
  (per person). A counter error lets the request through and is logged.
  Cloudflare's built-in rate-limiting binding was tried first and barely
  engaged when measured live (3 of 110 refused), so it was replaced; the
  replacement, measured live, let exactly 10 of a burst of 40 through. The
  dashboard
  shows "N of 50 reviews used this month". The Docker fallback has no AI
  allowlist: keep `AI_REVIEW` off there. A subscription and free trial are
  planned later.
- **Dashboard: pick or paste, push switch, clearing history (2026-10-21, user
  decisions).** A new user with no repositories sees one step, "Choose
  repositories on GitHub" (the App's install page); afterwards "Your
  repositories" (each with Review now, same limits as pasting) or "Paste a
  link". Per repository, its GitHub admins get a "Review every push" switch
  (`repo_settings`, migration 0007; on by default; off = the webhook ignores
  pushes, no check and no count) and "Clear history" (deletes its saved
  reports). Everyone has "Clear the reviews I started": deleted in
  repositories they administer, elsewhere only taken out of their view
  (`ran_by` set to NULL, still visible to admins), so nobody can erase the
  record of their own failed push. Uninstalling forgets the switches. All
  audited. Pasting an organisation repository the App is not on, as a
  non-admin, says only its owners can allow it.
- **The query check trusts tagged templates by name** (`SAFE_TAG`: `sql`, `db`,
  `query`), plus transaction tags (see above, 2026-10-20).

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

**Tools evaluated (2026-10-18), for reference.** *Claude Code Setup*
(Anthropic, official) is installed; its read-only scan recommended the hooks,
`/ship` and the planned reviewer above. *Fallow* (MIT, fallow-rs) is run on
demand with `npx fallow@3.34.1`, not installed: its first scan found a circular
import and an unlisted dependency (both fixed) plus `findAssignments` (removed
2026-10-20 with the other legacy code); its other findings are false positives (the
separate redirect and wall-check Workers, scripts run by hand, test fixtures
loaded by path, and `Reviewer.claim`, which is called over Cloudflare's RPC and
enforces "each outside step once" -- never remove it), so never use its
auto-fix. *NVIDIA SkillSpector* is a real open-source scanner for agent
skills; not installed, but worth running on any skill from outside the
Anthropic Directory before installing it. Not adopted: *Claude-Mem* (duplicates
CLAUDE.md, CLAUDE.local.md and built-in memory, and records every action,
secret-touching ones included); *Agent Reach* (acts through logged-in social
accounts via unofficial routes, and pulls text that can carry prompt
injection into a session holding Cloudflare and GitHub access); *Obsidian +
Graphify*-style code graphs (independent measurements show 13-34% savings on
medium projects, and a stale map misleads; Obsidian alone is a fine personal
notes app); *Everything Claude Code* (hundreds of generic skills, agents and
third-party hooks crowd the context and run code nobody chose; borrow single
pieces only); *Liner Model API* (checked 2026-10-18: a router that picks an
undisclosed model per request; "half price" is measured against OpenRouter's
cheapest model in a tier and the benchmarks are Liner's own, against Sonnet,
not Opus; OpenAI-style API only, so Claude Code cannot use it. ShipBrace makes
one optional AI call per review, so there is little to save, and sending code
excerpts to unnamed models would break the disclosure in
docs/legal/third-party-services.md. If cost matters later, try a cheaper
Claude model through `options.model` in `proposer.ts` and keep it only if
`scripts/bench.ts --model` still matches the perfect suggester with no
refusals); *Agent Skills* (addyosmani/agent-skills, MIT, checked 2026-10-18:
25 skills, 7 commands, 4 sub-agents; text only, its hooks are not wired into
Claude Code. Generic spec-to-ship advice that overlaps CLAUDE.md, `/ship` and
the built-in `/code-review`, `/simplify` and `/security-review`, and 25 skill
descriptions crowd the context. Worth borrowing: the layout of
`agents/code-reviewer.md` as a starting shape for `conventions-reviewer`.
Its `security-auditor` agent is a model judging code by checklist, so it
must never feed the product's findings. It is useful for auditing ShipBrace
itself: the built-in `/security-review` only covers pending changes, while
the auditor can review the whole system. Its checklist is also worth
reading as a list of detector ideas for the 16 items with none);
*Ponytail* (DietrichGebert/ponytail, MIT, v5.3.2, checked 2026-10-18: the
"-53% code" is the author's own benchmark; an independent JetBrains test is
reported at about 15% less code and 10% lower cost, and an earlier 80-94%
claim was withdrawn. The plugin runs its own Node scripts on every session
start and prompt, logs per-turn costs to `~/.config/ponytail/`, and can send
them to a webhook. Its useful idea fits in two lines of CLAUDE.md and needs
no plugin; any "less code" pressure must never trim a detector, a test or an
`undecidable` branch; the user declined adding it, 2026-10-18); *MiroFish*
(666ghj/MiroFish, AGPL-3.0, ~80k stars, checked 2026-10-18: a separate
Python app, not a Claude Code tool, that simulates a crowd of AI personas
reacting to your material. Its predictions are not validated anywhere we
found, and it sends the material to an OpenAI-style model (Alibaba's Qwen by
default) and to Zep Cloud for agent memory. Not useful before launch;
before opening up, a handful of real AI-app builders beat simulated ones).
Rule of thumb: prefer the Anthropic Directory, check viral
claims against the source, and read any outside skill before installing it.

## Roadmap

Done: review history (2026-10-09), the sealed reviewer (2026-10-09), hosting
on Cloudflare (2026-10-10), sign-in with GitHub, paste-a-link, notices and
per-installation switches (2026-10-10), the name ShipBrace, a public
repository with CI and a README screenshot, a dead-code cleanup, and the
Claude Code setup above (2026-10-18).

**The smarter checker (agreed 2026-10-18, widened and built 2026-10-20),**
roadmap item 6 below. Steps 1-5 are committed and tried on the practice
apps (see Current state); not yet pushed or deployed.
Every new check gets benchmark cases (a real problem and a safe look-alike),
keeps zero false alarms, is tried on the practice apps, and fills a checklist
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
2. **Opening up:** make the GitHub App public, widen `ALLOWED_GITHUB_USERS`,
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
