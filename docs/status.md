# Where work stopped

Moved from CLAUDE.md "Roadmap -> Next steps" on 2026-11-12. Read at the
start of a session; update it in the same change as the work it
describes.

**State:** last deployed commit `3b64bf6` (2026-11-15: the keystone
checker fixes, PR #7), live version `b008b46d`; `master` is at `3559137`
(the cleanup, PR #8), not deployed, which rides with the next real change.
Before them the same day: `49c3b04` / `889dfd2d` (the nightly
refused-attempts alert is also emailed), `062d229` / `24b26b6a` (someone else's review answers like
a missing one), `80452ce` / `47728c6e` (the dashboard says why a review
stopped; migration 0009 applied) and `b12fc6e` / `bb2c10ac` (a review
refuses with a plain message when GitHub's hourly allowance is short).
Since 2026-11-14 `master` takes changes only through a pull request whose
"test" check passed (GitHub ruleset "Protect master", no bypass); deploy
from `master` after merging. A database restore was practised on a
throwaway copy on 2026-11-15: every table matched. 476 tests.

1. **The AI cleaner step: live since 2026-11-11, not yet seen running**
   (Murat's decisions, 2026-11-10: Haiku 5.5 for his reviews only, neutral
   mark when softened, ping sample changed). What it is and how it is
   wired: CLAUDE.md "The one rule" and "Cleaner step built for going live" in
   `.claude/rules/checker.md`. Still to see:
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
   2026-11-11** (`protectionShown` in CLAUDE.md's conventions; the
   password-hashes item, session set-up and redirect-only pages in
   `.claude/rules/checker.md`).
   **Offered, not started:**
   - bringing the unused Docker setup in `deploy/` in line with Cloudflare
     (limits, records, who may use the AI step) before anyone uses it;
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
3. **Keystone false alarms: merged 2026-11-15 as PR #7 (`3b64bf6`), live
   as version `b008b46d`.** A live review
   of keystonejs/keystone gave 56 "need fixing": 44 false alarms, 8 true
   in sample code, 4 real. Four checker fixes (version ranges a lockfile
   records; an age limit where passes are checked; every-website CORS
   inside a choice; passport's sign-in start), each in
   `.claude/rules/checker.md`. Rules alone on keystone: 56 -> 12 need
   fixing, 9 -> 11 need checking. Benchmark and DVNA unchanged; NodeGoat's
   version item now passes (it saves a lockfile); Juice Shop's two version
   cards are one. Set aside: grouping identical findings and labelling
   sample folders (Murat's decision).
4. **Sign-in steps before pages (setup item 10): built 2026-11-15 on
   branch `checker/site-wide-sign-in`, not pushed.** Steps in `app.use(...)`
   are read for what they do, in order and across files (Fable planned,
   Opus built). Practice apps, rules alone: Juice Shop 52 -> 106 need
   fixing (54 pages lost a cover they never had; about 9 of them check
   sign-in inside their own code), NodeGoat 6 -> 7, DVNA and keystone
   unchanged. Next, offered: reading sign-in checks inside named handlers
   in other files, which removes those false alarms; and fewer "needs your
   check" cards, by reading a step's exempt addresses (`/login`,
   `OPTIONS`) and following path aliases and re-exporting index files. Details in
   `.claude/rules/checker.md`.
5. **Opening up** (needs Murat's product decisions): see CLAUDE.md, "Before anyone
   else uses it".

Done: review history (2026-10-09), the sealed reviewer (2026-10-09), hosting
on Cloudflare (2026-10-10), sign-in with GitHub, paste-a-link, notices and
per-installation switches (2026-10-10), the name ShipBrace, a public
repository with CI and a README screenshot, a dead-code cleanup, and the
Claude Code setup (2026-10-18; `docs/claude-code-tools.md`).

**The smarter checker (agreed 2026-10-18, widened and built 2026-10-20),**
CLAUDE.md roadmap item 6. Steps 1-5 are done, tried on the practice apps (see
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
