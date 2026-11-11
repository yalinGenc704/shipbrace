import Anthropic from "@anthropic-ai/sdk";
import { CASES } from "../packages/guardrails/bench/cases.ts";
import { falseAlarms, grade, type Score } from "../packages/guardrails/bench/grade.ts";
import { createClaudeCleanerJudge } from "../packages/guardrails/src/index.ts";

/**
 * The cleaner experiment (2026-11-10): the benchmark with an AI reading the
 * apps' own cleaning functions, against the rules alone. Costs API credit.
 *
 *   node --experimental-strip-types --env-file=.env scripts/bench-cleaners.ts [--runs 3] [--models haiku,opus]
 *
 * Kept only if every run proves the five broken cleaners, takes the six
 * correct ones off "Needs fixing", and adds no other false alarm.
 */

// US$ per million tokens, from the Claude API reference (prices cached 2026-11-03).
const MODELS = {
  haiku: { id: "claude-haiku-5-5", input: 0.1, output: 0.5 },
  opus: { id: "claude-opus-5-5", input: 4, output: 20 },
} as const;

const flag = (name: string): string | undefined => {
  const at = process.argv.indexOf(name);
  return at === -1 ? undefined : process.argv[at + 1];
};
const runs = Number(flag("--runs") ?? 3);
const chosen = (flag("--models") ?? "haiku,opus").split(",") as Array<keyof typeof MODELS>;

type Outcome = Score["outcomes"][number];
const cleanerCases = new Set(
  CASES.filter((c) => c.id.startsWith("homemade") || c.id === "number-parse-int-direct").map((c) => c.id),
);
const keyOf = (o: Outcome): string => `${o.caseId}:${o.entry.marker}`;
const shown = (o: Outcome): string =>
  o.reported ? (o.by === "cleaner-check" ? "AI finding" : "finding") : o.lead ? "worth a look" : "silent";

const baseline = await grade(CASES, "rules");
const before = new Map(baseline.outcomes.map((o) => [keyOf(o), shown(o)]));
console.log(`rules alone: ${baseline.real.found}/${baseline.real.total} found, ${falseAlarms(baseline)} false alarms`);

const client = new Anthropic();
for (const name of chosen) {
  const model = MODELS[name];
  for (let run = 1; run <= runs; run++) {
    let input = 0;
    let output = 0;
    const judge = createClaudeCleanerJudge(client as never, {
      model: model.id,
      onUsage: (usage) => {
        input += usage.input_tokens;
        output += usage.output_tokens;
      },
    });
    const score = await grade(CASES, "rules", undefined, { cleanerJudge: judge });
    const cost = (input * model.input + output * model.output) / 1_000_000;
    console.log(
      `\n=== ${name} run ${run}: ${score.real.found}/${score.real.total} found ` +
        `(${score.real.byCleaner} by the AI cleaner check), ${score.safe.cleared}/${score.safe.total} safe cleared, ` +
        `${falseAlarms(score)} false alarms; ${input} in / ${output} out tokens, about $${cost.toFixed(4)}`,
    );
    for (const o of score.outcomes) {
      const now = shown(o);
      const was = before.get(keyOf(o));
      if (!cleanerCases.has(o.caseId) && now === was) continue;
      const right = o.entry.real ? now.endsWith("finding") : !now.endsWith("finding");
      const why = o.reported && !o.entry.real && o.explanation ? `  (${o.explanation.slice(0, 160)})` : "";
      console.log(`  ${right ? "ok " : "BAD"} ${o.caseId.padEnd(40)} ${o.entry.real ? "real" : "safe"}  ${was} -> ${now}${why}`);
    }
    for (const u of score.unexpected) console.log(`  BAD unexpected risk in ${u.caseId}: ${u.risk.what.slice(0, 120)}`);
  }
}
