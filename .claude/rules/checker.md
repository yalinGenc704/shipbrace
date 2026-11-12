---
paths:
  - "packages/**"
  - "scripts/**"
---

# Current state: the checker and the starter kit

Moved word for word from CLAUDE.md "Current state and known gaps" on
2026-11-12. Claude Code loads this file when a matching file is opened;
keep it true in the same change as the code, like CLAUDE.md. The
benchmark scores stay in CLAUDE.md.

- **Cleaner step, as first measured (2026-11-10, see "The one rule").**
  Haiku 5.5 and Opus 5.5, three runs each plus one after the review fixes,
  gave identical answers: all 5 broken home-made cleaners became
  `cleaner-check` risks (37 -> 42 of 46 found) and 5 of the 6 correct ones
  became "worth a look" (6 -> 1 false alarms). Both models judge
  `homemade-clean-host` unsafe (a value starting with a dash would be read
  by ping as an option); the answer key said safe, since ping then stops
  with no address. Haiku said safe there in 2 of 8 runs, Opus never: the
  only answer that varied. No other case changed. DVNA, NodeGoat, Juice Shop and
  ShipBrace have no home-made cleaner on a traced path, so nothing was asked
  there. Cost per benchmark run: about $0.002 (Haiku) and $0.07-0.08
  (Opus). Not followed yet: CommonJS `require`, chains through a second
  name.
- **Cleaner step built for going live (2026-11-10, Murat's decisions: Haiku
  5.5, his reviews only, neutral mark when softened, ping sample changed).**
  The sample's `clean` now also drops leading dashes, so "safe" is plainly
  right; two fresh Haiku runs: 42 of 46 found (5 by the cleaner check), 49
  of 49 safe cleared, 0 false alarms, about $0.002 per run, and roughly 830
  input and 65-400 output tokens per function asked (well under a tenth of
  a cent each; at most 30 per review). Rules alone are unchanged (37 and 40
  of 46, the same 6 known false alarms, the ping sample among them). Wiring: the
  outside step `judge` (`cloud/src/outside-steps.ts` `answerJudge`,
  `reviewer.ts`, allowed by `review-container.ts`; `sandbox/worker.ts`,
  `sandbox.ts` and `reviewer-http.ts` on the reviewer's side). The Worker
  logs the step's token counts (numbers only). The sandbox now refuses a
  step name it does not know (it used to fall through to the package
  lookup). The Docker fallback does not carry the step (`remote.ts`,
  `reviewer.ts` unchanged; `AI_CLEANER_CHECK=on` with `REVIEWER_SOCKET`
  refuses to start). The dashboard report says what the step did
  (`CleanerNote`). The model's own sentence is shown only as one plain
  sentence (`plainReason`, applied to every judge in `applyVerdicts`: no
  address, markup, hidden characters or attack text, else a fixed sentence)
  and is left out of the "exact fix" meant for pasting into an AI
  assistant. A judge given malformed questions fails, and the report says
  the step did not run. The notices and the AI switch describe the step
  (`NOTICE_VERSION` bumped, so everyone is asked again), and
  `docs/legal/third-party-services.md` sections 2 and 5 cover it. Deployed
  2026-11-11. Its first true end-to-end run on Cloudflare is the first
  review, after that, of an app with a home-made cleaner: read the Worker
  log line "cleaner check (...)" for the real cost.
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
  (detected from packages, its folder, or an import in real code; since
  2026-10-25 not in tests or quoted text, and when `supabase/` SQL creates
  tables only that SQL is judged, so another database in the same
  repository is left alone)
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
- **Practice apps after the 2026-11-10 changes:** DVNA 21 risks (the
  `/redirect` false alarm gone, nothing else changed), NodeGoat 7 and Juice
  Shop 53 as before. NodeGoat's protective-headers and CSRF items went from
  pass to handed back: its helmet and csurf lines are inside a commented-out
  block, so both had been false passes. ShipBrace reviewing itself (rules
  alone, no package lookup): 0 risks; "how passwords are stored" and the
  rate-limit item went from pass to handed back (both had passed on words
  in ShipBrace's own text; its real limiter has names the check does not
  know, and answers 429).
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
- **Site-wide middleware as a sign-in check (gap noted 2026-10-23, narrowed
  2026-11-10).** `app.use(...)` of session set-up (`session({...})`,
  `cookieSession`, `passport.initialize()`/`.session()`, flash) no longer
  counts as a sign-in check, and for any call only what is called counts,
  not the settings passed to it (`cors({ origin: allowedOrigins })`), so an
  Express app with sessions and no check gets its open pages reported
  (`SESSION_SETUP`, `guardNamesIn`). `app.use(require("..."))` in any shape
  still counts, as the app's own check may be loaded that way, unless the
  package is one known only to set things up (`SETUP_PACKAGE`). Still
  counted, erring to silence: any other name not in `NOT_A_GUARD`, and a
  function written inline in `app.use`. Measured on DVNA, NodeGoat and Juice Shop: no change, since
  their routes sit in router files or behind other site-wide names. Juice
  Shop's open redirect is guarded by a bypassable allowlist and its
  redirect item shows a pass.
- **Redirect-only pages (2026-11-10, `Door.onlyRedirects`).** A handler
  with nothing running before it that only calls `redirect` or an answer
  method on its answering parameter, and reads only one field of the
  address or the query, has nothing for a sign-in to protect, so it is not
  reported as open. Its code may hold nothing else: no other name, call,
  variable, nested function, `await`, `new` or `import()`. A handler named
  rather than written inline is trusted only when the route's own file
  shows where the name comes from and that file hands the function out
  under it (`const h = require("./f")` with `module.exports.name =`, a
  named import of an exported function, `import * as h`, or a declaration
  at the top of the same file; the name bound once in the route's file,
  and handed out exactly once by a file that never replaces
  `module.exports`): a same-named method on some object, a default
  import, or an unrelated function elsewhere, never stands in. Where the page sends people is still the
  traced open-redirect risk. DVNA's `/redirect` was its one false alarm
  (22 -> 21 risks; its open-pages item now passes).
- **The password-hashes item names what it found (2026-11-10).** When the
  project describes its tables (`modelFields`) and none has a column that
  could hold a password under any usual name, the item says so instead of
  "couldn't find a description"; still handed back, never passed or absent,
  and it does not claim there are no passwords (they can live in a store
  with no written description).
- 16 of 50 checklist items have no detector and are left to the user (counted 2026-10-23; the open-redirect item was split out of file paths). The
  checklist follows OWASP Top 10:2025; the four items added for its new
  categories (A03 supply chain, A10 exceptional conditions) have no detector yet.
- **Code from other websites (2026-10-25, `pages:script-integrity`).** Page
  files (html and template types, jsx/tsx) are read for script and
  stylesheet tags. An outside address without the tag's own
  `integrity="sha…"` is a low risk that may be intended (the risk names
  only the host). Services that ask not to be locked (Google Fonts, Stripe,
  reCAPTCHA, Turnstile…) are a notice. A placeholder or expression address,
  an import map, an import from a web address, head settings in code or
  scripts added at run time hand the item back. Pass only when every
  address is the site's own or locked. The reader also reads `.jsonc` and
  `.json5` now, and the CSRF check counts `Set-Cookie` headers and
  `SameSite=Lax/Strict` in them.
- **Database reachable from outside (2026-10-25, `compose:no-public-database`).**
  Reads every Docker Compose file (`COMPOSE` in `review/project-files.ts`:
  `compose.yaml`, `docker-compose.yml`, overrides), merging services by name
  within one folder only. A database image (judged by the image's own name,
  not its registry) that publishes a port not bound to 127.0.0.1, or uses
  `network_mode: host`, is a high risk (medium in dev/test files). Shared
  blocks that touch ports or images, `extends:`, `include:`, flow-style or
  old-format files, and unread compose files hand the item back.
- **The query check trusts tagged templates by name** (`SAFE_TAG`: `sql`, `db`,
  `query`), plus transaction tags (see above, 2026-10-20), and since
  2026-10-25 queries whose pasted pieces are all fixed text (`isFixedText`):
  `.map(() => "?").join(",")`, `$${i + 1}` on a plain array, a `const` of
  fixed text declared once in an enclosing block, a choice between fixed
  pieces. Known gap: a name holding a lodash/Immutable wrapper, whose `.map`
  passes keys, is trusted like an array.
