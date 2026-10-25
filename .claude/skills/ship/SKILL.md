---
name: ship
description: Deploy ShipBrace to Cloudflare (app.shipbrace.com) and check the live site afterwards. Only when the user types /ship.
disable-model-invocation: true
---

# Ship ShipBrace

Deploys the current code to Cloudflare, then proves the live site still behaves.
Never run this without the user typing `/ship`: it changes what real visitors get.

Work from the repository root. Stop and report at the first step that fails;
never deploy past a failing check.

## 1. Before deploying

1. `git status --short` must be empty, and the branch must not be behind
   `origin/master`. Deploy only what is committed, so the live site always
   matches a commit.
2. Run the same checks CI runs, and stop if any fails:
   - `npm run typecheck`
   - `npx oxlint .`
   - `TEST_DATABASE_URL=postgres:///shipbrace_test npm test` (start PostgreSQL
     first if needed; see CLAUDE.md, "Running things")
   - `npm run bench`: the scores must not drop below the latest ones in
     CLAUDE.md ("Current state and known gaps", the Benchmark line), which
     wins if it differs from this note. On 2026-10-20: rules alone 36 of 40,
     perfect suggester 39 of 40, 42 of 42 safe decoys cleared, 0 false
     alarms.
3. If `cloud/migrations/` has a migration not yet applied on Cloudflare
   (`cd cloud && npx wrangler d1 migrations list aegis-history --remote`), tell
   the user which one and apply it with `--remote` before deploying the code.
4. Docker must be running for the reviewer image (`colima start` if not).

## 2. Deploy

```bash
npm run build
cd cloud && npx wrangler deploy
```

The reviewer image is built for linux/amd64 through emulation; it can take a
few minutes. Report the version ID wrangler prints.

## 3. Check the live site

All of these must hold; report each result plainly:

| Check | Expected |
| --- | --- |
| `curl -s -o /dev/null -w '%{http_code}' https://app.shipbrace.com/api/health` | `200` |
| `curl -s https://app.shipbrace.com/api/me` | `{"signedIn":false,...}` (sign-in configured, nobody signed in) |
| `curl -sI https://app.shipbrace.com/` | a `content-security-policy` header starting `default-src 'self'` |
| `curl -s https://app.shipbrace.com/robots.txt` | `Disallow: /` |
| `curl -s -o /dev/null -w '%{http_code}' -X POST https://app.shipbrace.com/api/github/webhook -d '{}'` | `401` (unsigned messages refused) |
| `curl -s -o /dev/null -w '%{http_code}' https://app.shipbrace.com/api/review` | `404` (no folder review on Cloudflare) |

If any check fails, say so first, then offer to roll back with
`cd cloud && npx wrangler rollback`.

## 4. Report

One short summary in plain language: what was deployed (the commit), the
version ID, and the result of every check.
