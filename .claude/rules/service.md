---
paths:
  - "cloud/**"
  - "server/**"
  - "app/**"
  - "deploy/**"
  - "Dockerfile"
---

# Current state: ShipBrace's own service

Moved word for word from CLAUDE.md "Current state and known gaps" on
2026-11-12. Claude Code loads this file when a matching file is opened;
keep it true in the same change as the code, like CLAUDE.md. The
benchmark scores stay in CLAUDE.md. The AI cleaner step's wiring on
Cloudflare (`outside-steps.ts`, `reviewer.ts`, the sandbox, `CleanerNote`,
`NOTICE_VERSION`) is described in `.claude/rules/checker.md`, "Cleaner step
built for going live".

- **The check's mark (2026-10-01, extended 2026-11-10):** failure with a
  proven high risk; neutral with other proven risks, or with none but a
  finding an AI moved to "worth a look" (the title then reads "N finding(s)
  an AI thinks is safe, for you to confirm"); success otherwise.
- **GitHub App works end to end (first live run 2026-10-01):** App ID 5157570
  (address github.com/apps/shipbrace; it was "yg-aegis-review" until renamed,
  and the old address now gives "not found"), installed only on the private test repo
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
  (`maxWaiting` 50, then refused as "busy"). Rate limiting is in the Worker
  (see "Review limits, AI access and rate limiting").
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
- **Self-review (2026-10-25, from the dashboard):** 13 "needs fixing", 2
  were package warnings (see `CLAUDE.local.md`). The other 11 and 8 of 9 query notes came from reading
  text about code as code; fixed the same day (see "Text about code is not
  code"). The last note, `cloud/src/accounts.ts` pasting column names from a
  fixed list into `SET col = ?`, was removed by rewriting it as one fixed
  `COALESCE` statement; the report's suggested fix (`?` placeholders) could
  not have worked there, since `?` only stands for values. `crypto/no-password-hashes-sent` went from pass to handed
  back: ShipBrace has no password fields, it had passed on benchmark text.
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
- **Audit fixes (2026-11-11, after the audit of 2026-11-10).** The invite
  list is `ALLOWED_GITHUB_IDS`: GitHub account numbers, or the single word
  `everyone`; missing or empty lets nobody in (it used to list names, and
  empty meant everyone). Signed-in requests are limited to 16 KB, counted
  as they arrive. Every sentence in the GitHub check's summary passes
  through `inline()`, which now also collapses runs of backticks and
  breaks bare web addresses so GitHub does not link them. Someone taken
  off the invite list has their session and stored token deleted at their
  next request. The AI suggestion call has a 5-minute limit and one
  retry, like the cleaner call's 2 minutes. wrangler 4.160.0 and seroval
  1.8.1 (a dashboard dependency of the router): `npm audit` reports no
  known flaws.
- **Set-aside work built 2026-11-11 (Murat's go-ahead).**
  *Repeated webhook deliveries* (`cloud/src/deliveries.ts`, migration
  0008): a push GitHub delivers twice (its retry, or Redeliver) is
  acknowledged and not reviewed or counted again; ids kept a week, and only
  for signed messages that start a review. To review a commit again, use
  "Review now" on the dashboard. *Nightly alert* (`refusedLastDay`,
  `alertLine` in `cloud/src/audit.ts`): five or more refused attempts in 24
  hours write one log line starting `SHIPBRACE-ALERT`; a sign-in refused by
  the invite list is counted without keeping who it was. It is a log line
  only: nothing emails anyone. *Delete my account* (`POST
  /api/account/delete`, the person's own GitHub name typed to confirm):
  deletes every session and stored token, the person's record, and the
  reviews they started by the same rule as "Clear the reviews I started";
  asks GitHub to end the App's access to their account (best effort).
  Installations, repository settings and audit-log entries stay. *Dashboard*:
  an address that leads nowhere shows "This page doesn't exist" (the answer
  is still 200: Cloudflare serves the page itself for every address), a
  favicon and a description. A year's caching for `/assets/*` was tried
  and taken out the same day: Cloudflare answers a made-up name under
  `/assets/` with the page itself, and the rule gave that answer the
  year-long caching too. To bring it back, missing assets must first
  answer 404 instead of the page.
- **Dashboard: pick or paste, push switch, clearing history (2026-10-21, user
  decisions).** A new user with no repositories sees one step, "Choose
  repositories on GitHub" (the App's install page); afterwards "Your
  repositories" (each with Review now, same limits as pasting) or "Paste a
  link". Per repository, its GitHub admins get a "Review every push" switch
  (`repo_settings`, migration 0007; on by default; off = the webhook ignores
  pushes, no check and no count) and "Clear history" (deletes its saved
  reports). Everyone has "Clear the reviews I started": deleted in
  repositories they administer (together with reports linked to nobody:
  kept before 2026-10-18, or hidden by others), elsewhere only taken out of their view
  (`ran_by` set to NULL, still visible to admins), so nobody can erase the
  record of their own failed push. Uninstalling forgets the switches. All
  audited. Pasting an organisation repository the App is not on, as a
  non-admin, says only its owners can allow it.
