# Where work stopped

Moved from CLAUDE.md "Roadmap -> Next steps" on 2026-11-12. Read at the
start of a session; update it in the same change as the work it
describes.

**State:** everything is pushed and deployed (2026-11-11): last deployed
commit `97fbf54`, live version `40ddc80d`, all six live checks passed. The
audit fixes and the set-aside work are live, migration 0008 is applied, and
the year-long asset caching is taken out again. Murat signed in after the
deploy with the invite list by account number (audit log, 2026-11-12), and
accepted the new notices. 431 tests.

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
3. **Opening up** (needs Murat's product decisions): see CLAUDE.md, "Before anyone
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
