import assert from "node:assert/strict";
import { test } from "node:test";
import { CASES } from "../bench/cases.ts";
import { falseAlarms, grade } from "../bench/grade.ts";

/**
 * The benchmark as a ratchet. Scores may rise; these tests stop them falling.
 *
 * When a change improves a number, raise the floor here in the same commit, so
 * the improvement cannot be lost later without someone noticing.
 */

const traced = (score: Awaited<ReturnType<typeof grade>>) =>
  score.outcomes.filter((o) => !o.entry.real && o.by === "oracle");

test("the checker never reports safe code as a proven problem", async () => {
  // Pattern-check alarms are a known, separate issue. A false alarm from the
  // checker itself would break the one promise the design makes.
  for (const mode of ["rules", "perfect"] as const) {
    const score = await grade(CASES, mode);
    assert.deepEqual(
      traced(score).map((o) => o.caseId),
      [],
      `${mode}: the checker confirmed a path through safe code`,
    );
  }
});

test("rules alone prove at least the baseline", async () => {
  const score = await grade(CASES, "rules");
  assert.ok(score.real.proven >= 17, `proven ${score.real.proven}, baseline 17`);
  // Unproven leads still surface real problems, under "worth a look".
  const surfaced = score.real.found + score.real.leads;
  assert.ok(surfaced >= 18, `surfaced ${surfaced}, baseline 18`);
});

test("a perfect suggester gets at least the baseline confirmed", async () => {
  const score = await grade(CASES, "perfect");
  assert.ok(score.real.proven >= 19, `proven ${score.real.proven}, baseline 19`);
});

test("a good suggester adds findings the rules cannot raise alone", async () => {
  // The ownership cases: only a suggester can judge which records are private.
  const rules = await grade(CASES, "rules");
  const perfect = await grade(CASES, "perfect");
  assert.ok(perfect.real.proven > rules.real.proven, "the suggester step should contribute");
});

test("no safe code is reported as a risk", async () => {
  // Safe code may appear under "worth a look"; it may never be called a risk.
  for (const mode of ["rules", "perfect"] as const) {
    const score = await grade(CASES, mode);
    assert.equal(falseAlarms(score), 0, `${mode}: safe code reported as a risk`);
  }
});
