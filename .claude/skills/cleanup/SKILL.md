---
name: cleanup
description: Remove unused code from ShipBrace with Fallow and /simplify, then prove no detector, test, benchmark case or undecidable branch was lost. Only when the user types /cleanup.
disable-model-invocation: true
---

# Clean up ShipBrace

Removes code nothing uses and simplifies what is left, without weakening the
checker. Work from the repository root (`aegis/`), on a clean working tree
(`git status --short` empty), so the diff shows only the cleanup. Commit
nothing: Murat reads the result first.

## What must never be removed

A detector, a test, a benchmark case, or an `undecidable` branch. Less code
is not a reason. A check that looks unused may be the only thing between a
user and a false pass. Test files and `packages/guardrails/bench/` are not
edited at all during a cleanup. `scripts/cleanup-guard.ts` enforces this
(step 4); it cannot be argued with, only satisfied.

## 1. Find unused code

```bash
npx fallow@3.34.1
```

Never its auto-fix. Skip these known false alarms; they are used, just not
in a way Fallow can see (`docs/claude-code-tools.md`):

- `Reviewer.claim`: called over Cloudflare's RPC; it enforces "each outside
  step once".
- The separate Workers: the redirect Worker and `cloud/wall-check/`.
- Scripts run by hand (`scripts/`).
- Test fixtures loaded by path.

List what is left for Murat in plain language (file, what it is, why it
looks unused) before removing anything that is not plainly dead (an unused
import, a helper with no caller anywhere).

## 2. Remove the agreed items

Remove only what step 1 listed. Search the whole repository for each name
first (`grep -rn`), including `cloud/`, `app/` and string uses.

## 3. Simplify

Run `/simplify` on the changed code. It may merge repeats and shorten code;
it may not change what a check finds or what the report says, and it may not
touch test or benchmark files.

## 4. The guard

```bash
node --experimental-strip-types scripts/cleanup-guard.ts
```

It compares the files now with the last commit. It fails if any test or
benchmark file changed, or if anything protected in the checker code is
gone: rule and check ids, checklist detector names, the members of the
lists that switch detectors on or decide risk versus lead, the kinds of
dangerous operation, exported names, the entries of ALL_CAPS constants, and
mentions of `undecidable`. Comments are removed first, so commenting
something out counts as removing it; a renamed or moved one counts as gone.

- **FAIL:** put every listed item back, exactly as it was, and run it again.
  Tell Murat what had been removed. If one truly must go, stop and ask him;
  never edit the guard to make it pass.
- **OK** means no protected name is gone. It does not prove a kept check
  still works: steps 5 and 6 do.

## 5. Prove nothing changed

1. Start PostgreSQL (the `pg_ctl` line in CLAUDE.md, "Running things"), then
   `TEST_DATABASE_URL=postgres:///shipbrace_test npm test`: the count in
   CLAUDE.md, all pass (without the database 6 skip; say so).
2. `npm run bench`: every score exactly as before, the same false alarms.
   Any change, better or worse, means behaviour changed: undo that part.
3. `npm run typecheck && npx oxlint .`

## 6. Read and report

Read `git diff` for every deletion in `packages/guardrails/src/analysis/`
(the tracing and the verifier) and say in one line why each is safe.

For Murat, in plain language: what was removed and why it was unused, the
guard's result, the test and benchmark numbers, and `git diff --stat`.
Leave it uncommitted. Run `conventions-reviewer` (checker files) or
`security-auditor` (service files) on the diff before he commits.
