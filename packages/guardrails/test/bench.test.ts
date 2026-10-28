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

/**
 * Safe code the checker still reports, each a case written to show a known
 * gap (2026-10-27): correct home-made cleaners with plain names, or called
 * inside the dangerous line, are not recognised. Keyed by case and marker.
 * Listed so any *other* false alarm still fails, and so a fix must shrink
 * this list -- the test below fails while a listed one is no longer reported.
 */
const KNOWN_FALSE_ALARMS = new Set([
  "homemade-to-safe-id:A",
  "homemade-only-digits:A",
  "homemade-pick-column:A",
  "homemade-clean-host:A",
  "homemade-encode-html:A",
  "homemade-escape-html-inline:A",
]);
const keyOf = (o: { caseId: string; entry: { marker: string } }) => `${o.caseId}:${o.entry.marker}`;

test("the checker never reports safe code as a proven problem", async () => {
  // Pattern-check alarms are a known, separate issue. A false alarm from the
  // checker itself would break the one promise the design makes.
  for (const mode of ["rules", "perfect"] as const) {
    const score = await grade(CASES, mode);
    assert.deepEqual(
      traced(score).map(keyOf).filter((id) => !KNOWN_FALSE_ALARMS.has(id)),
      [],
      `${mode}: the checker confirmed a path through safe code`,
    );
  }
});

test("rules alone prove at least the baseline", async () => {
  const score = await grade(CASES, "rules");
  assert.ok(score.real.proven >= 29, `proven ${score.real.proven}, baseline 29`);
  // Unproven leads still surface real problems, under "worth a look".
  const surfaced = score.real.found + score.real.leads;
  assert.ok(surfaced >= 30, `surfaced ${surfaced}, baseline 30`);
});

test("a perfect suggester gets at least the baseline confirmed", async () => {
  const score = await grade(CASES, "perfect");
  assert.ok(score.real.proven >= 32, `proven ${score.real.proven}, baseline 32`);
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
    const reported = score.outcomes.filter((o) => !o.entry.real && o.reported).map(keyOf);
    assert.deepEqual(reported.filter((id) => !KNOWN_FALSE_ALARMS.has(id)), [], `${mode}: safe code reported as a risk`);
    assert.equal(score.unexpected.length, 0, `${mode}: a risk on a line the key does not mark`);
    assert.equal(falseAlarms(score), reported.length, `${mode}: false alarms counted differently`);
  }
});

test("a known false alarm that is fixed comes off the list", async () => {
  for (const mode of ["rules", "perfect"] as const) {
    const score = await grade(CASES, mode);
    const reported = new Set(score.outcomes.filter((o) => !o.entry.real && o.reported).map(keyOf));
    for (const id of KNOWN_FALSE_ALARMS) {
      assert.ok(reported.has(id), `${mode}: ${id} is no longer a false alarm -- remove it from KNOWN_FALSE_ALARMS`);
    }
  }
});
