---
name: new-check
description: Steps for adding or widening a ShipBrace detector (a rule, a project check, a new kind of dangerous operation, or a checklist item's detector) in packages/guardrails. Use when the user types /new-check, or before writing any new detector.
---

# Add a detector to ShipBrace

A detector is the code that answers one checklist item or finds one kind of
risk. Every one goes through the same steps, so none can pass falsely, warn
on correct code, or slip in without proof. Work from the repository root
(`aegis/`). Stop and tell Murat at the first step that fails.

The rules behind these steps are in CLAUDE.md ("The one rule", "Conventions
that are load-bearing"); read them first if this session has not.

## 1. Agree what it finds, before code

Write, in plain language, for Murat:

- the checklist item it answers (`packages/guardrails/src/review/modules.ts`)
  and whether it finds **risks** (proven: traced, or the problem itself) or
  only **leads** ("worth a look": the rule goes in `UNPROVEN_RULES`);
- exactly what it covers and what it does not (this becomes the item's
  `covers` text, "Checked: ...");
- when the item goes back to the user instead of passing (the thing could
  exist out of the check's sight), and when, if ever, it is `absent`.

If any of this changes how ShipBrace behaves for users, wait for his OK.

## 2. Benchmark cases and tests first

In `packages/guardrails/bench/cases.ts` add at least two cases, before the
detector:

- **the real problem**, with the answer key marking it;
- **a safe look-alike**: code that looks the same but is correct (fixed text,
  a real cleaner, a guard). A detector that fires here is a defect.

Add unit tests next to the detector's neighbours (`test/checks.test.ts`,
`review.test.ts`, `leads.test.ts`, `mass.test.ts`...): it finds the problem,
stays quiet on the look-alike, and hands the item back where it cannot run.

Run `npm run bench` and keep the scores from before the change.

## 3. Write the detector

Where it goes depends on its kind:

- **A per-file rule:** `src/rules/`, in its file's rule list; a new rules
  file's list is added to `allRules` (`src/engine.ts`).
- **A project-level check:** `src/review/checks.ts` or `project-files.ts`,
  in `projectChecks` (or `fileChecks`).
- **A new kind of dangerous operation** (as mass assignment, unsafe decoding
  and XML outside references were): a `SinkKind` in `analysis/inventory.ts`,
  found in `inventory-ast.ts`, followed by `oracle.ts` and `verify.ts`, with
  a `taint:<kind>` detector name; if only some cleaners protect it, extend
  `Sanitizer.protects` and `checksFor`.
- **A question that can be seen not to apply** (no detector): an entry in
  `applicability` in `checks.ts`, never overriding a project check.

In every case set the item's `detector` name in `modules.ts`, and:

- Patterns that look for a danger run on `codeOnly(file)`; patterns that
  look for a protection use `protectionShown` (a mention in a comment never
  passes an item). See "Text about code is not code".
- When unsure whether something is real, answer `undecidable` or hand the
  item back. Never `valid`, never a pass.
- `absent` only when the thing is clearly not in the project: files out of
  sight (`outOfSight()`, `snapshot.unread`) block it.
- Excerpts go through `redact()` before a finding exists; text taken from
  the repository goes through `cleanText`; a risk that can be right as it is
  carries `mayBeIntended`.
- Report text: at most three sentences each, page names instead of files,
  code only in `fixDetail`, none of the forbidden words (`test/plain-words.ts`).

## 4. Prove it

All must hold. Report each number plainly, misses included:

1. Start PostgreSQL (the `pg_ctl` line in CLAUDE.md, "Running things"),
   then `TEST_DATABASE_URL=postgres:///shipbrace_test npm test`: everything
   passes. Without the database 6 tests skip; say so if that happened.
2. `npm run bench`: no score drops below the latest in CLAUDE.md, the new
   real case is found, the look-alike is cleared, and no false alarm appears
   beyond `KNOWN_FALSE_ALARMS` in `test/bench.test.ts`. A new false alarm is
   never added to that list; a fixed one comes off it. If scores rose, raise
   the floors in `test/bench.test.ts` in the same change.
3. `npm run typecheck && npx oxlint .`
4. **The practice apps** in `~/shipbrace-test-repos` (dvna, NodeGoat,
   juice-shop; read-only, never install or run them). Review each with
   rules alone, before and after the change, with a scratch script in
   `$TMPDIR` (not in the repository) that calls `ingest` from
   `server/src/ingest.ts` and `runSecurityReview` from
   `packages/guardrails/src/index.ts`, as `scripts/simulate.ts` does without
   its model half. Compare risk and lead counts and the new item's status.
   Check every new finding by hand in the app's code: real or false alarm.

## 5. Write it down, review, commit

- Add a dated bullet to `.claude/rules/checker.md`: what it finds, what it
  does not cover, practice-app results. Weaknesses in ShipBrace's own
  service do not go in committed files (the repository is public); they go
  in CLAUDE.local.md.
- If an item gained its first detector, update the "16 of 50 checklist
  items have no detector" count in `checker.md` and the same count in
  `docs/claude-code-tools.md`. Update the benchmark line in CLAUDE.md if the
  scores moved, and `docs/status.md` if the work was on its list.
- Run `conventions-reviewer` on the diff (from the parent folder: a
  general-purpose agent told to follow `aegis/.claude/agents/conventions-reviewer.md`,
  on Sonnet). Fix what it finds.
- Commit locally. Ask Murat before pushing or deploying (`/ship`).
