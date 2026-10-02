import assert from "node:assert/strict";
import { test } from "node:test";
import { runSecurityReview, snapshotFromFiles } from "../../guardrails/src/index.ts";
import { generate } from "../src/index.ts";

/**
 * The starter kit is held to its own review. An app we generate must not
 * raise a single warning about its own code: if it did, either the kit ships
 * a hole or the review raises false alarms, and both are defects.
 *
 * The one expected exception is the lockfile, which is created on first
 * install, not by the generator.
 */
for (const spec of [
  { name: "demo", features: ["auth"], database: "postgres" },
  { name: "demo", features: [], database: "none" },
] as const) {
  test(`a generated app (${spec.features.join(",") || "no features"}) passes its own review`, async () => {
    const out = generate({ ...spec, features: [...spec.features] });
    const review = await runSecurityReview(
      snapshotFromFiles(out.files.map((f) => ({ path: f.path, content: f.contents }))),
    );
    const risks = review.modules
      .flatMap((m) => m.items.flatMap((i) => i.risks))
      .filter((r) => !r.id.startsWith("check/missing-lockfile"));
    assert.deepEqual(risks.map((r) => r.what), []);
  });
}
