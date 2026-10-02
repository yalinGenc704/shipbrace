import { CASES } from "../packages/guardrails/bench/cases.ts";
import { falseAlarms, grade, type Score } from "../packages/guardrails/bench/grade.ts";

/**
 * Scores the review against apps whose right answers are known.
 *
 *   node --experimental-strip-types scripts/bench.ts            rules + perfect suggester
 *   node --experimental-strip-types --env-file=.env scripts/bench.ts --model
 *                                                               also a real model (costs credit)
 *
 * Read the two numbers per mode: real problems found (higher is better) and
 * false alarms (must be zero). "perfect" is the ceiling the checker allows;
 * whatever it misses, no model can make the tool find.
 */

function report(score: Score): void {
  const label = {
    rules: "Rules alone (no AI)",
    perfect: "Perfect suggester (the most any AI could get confirmed)",
    model: "Real AI model",
  }[score.mode];

  console.log(`\n=== ${label}`);
  console.log(`  real problems proven:          ${score.real.found} of ${score.real.total}`);
  console.log(`  real problems "worth a look":  ${score.real.leads}`);
  console.log(`  safe code cleared:             ${score.safe.cleared} of ${score.safe.total}`);
  console.log(`  safe code "worth a look":      ${score.safe.leads}`);
  console.log(`  false alarms:                  ${falseAlarms(score)}`);
  if (score.mode !== "rules") {
    console.log(
      `  suggestions:                   ${score.proposals.made} made, ${score.proposals.confirmed} confirmed`,
    );
  }

  const guessed = score.outcomes.filter((o) => o.entry.real && o.lead);
  if (guessed.length > 0) {
    console.log('\n  real problems listed only as "worth a look" (not proven):');
    for (const o of guessed) console.log(`    - ${o.caseId} [${o.entry.marker}]: ${o.explanation}`);
  }

  const missed = score.outcomes.filter((o) => o.entry.real && !o.reported && !o.lead);
  if (missed.length > 0) {
    console.log("\n  missed:");
    for (const o of missed) {
      const who = o.suggested === false ? " (the AI never suggested it)" : "";
      console.log(`    - ${o.caseId} [${o.entry.marker}]${who}: ${o.entry.why}`);
      console.log(`        ${o.explanation}`);
    }
  }

  const wrong = score.outcomes.filter((o) => !o.entry.real && o.reported);
  if (wrong.length > 0 || score.unexpected.length > 0) {
    console.log("\n  FALSE ALARMS:");
    for (const o of wrong) {
      const how = o.by === "oracle" ? "traced" : "pattern check";
      console.log(`    - ${o.caseId} [${o.entry.marker}] (${how}): ${o.entry.why}`);
      console.log(`        reported as: ${o.explanation}`);
    }
    for (const u of score.unexpected) console.log(`    - ${u.caseId}: ${u.risk.what}`);
  }
}

const rules = await grade(CASES, "rules");
const perfect = await grade(CASES, "perfect");
report(rules);
report(perfect);

if (process.argv.includes("--model")) {
  const { default: Anthropic } = await import("@anthropic-ai/sdk");
  const { createClaudeProposer } = await import("../packages/guardrails/src/index.ts");
  const proposer = createClaudeProposer(new Anthropic() as never, { effort: "high" });
  report(await grade(CASES, "model", proposer));
}

console.log(`\n${CASES.length} sample apps.`);
