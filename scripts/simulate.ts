import Anthropic from "@anthropic-ai/sdk";
import { createClaudeProposer, runSecurityReview } from "../packages/guardrails/src/index.ts";
import { ingest } from "../server/src/ingest.ts";

/**
 * Does the model contribute findings the rules could not reach alone?
 *
 * The comparison is the whole point: the same repository is reviewed twice,
 * once with no model at all and once with one suggesting ways in. Any
 * difference is attributable to the model, and every finding on either side was
 * established by the rules.
 */
const root = process.argv[2] ?? process.cwd();
const { snapshot, fileCount } = await ingest(root, ".");

const countFindings = (r: Awaited<ReturnType<typeof runSecurityReview>>) =>
  r.modules.flatMap((m) => m.items.flatMap((i) => i.risks)).length;

const withoutModel = await runSecurityReview(snapshot);
console.log(`${fileCount} files | rules alone: ${countFindings(withoutModel)} findings, ${withoutModel.stats.exploitablePaths} proven paths\n`);

const proposer = createClaudeProposer(new Anthropic() as never, { effort: "high" });
console.log(`asking ${proposer.name} for ways in...\n`);

const started = Date.now();
const withModel = await runSecurityReview(snapshot, { proposer });
const elapsed = ((Date.now() - started) / 1000).toFixed(1);

const before = new Set(
  withoutModel.modules.flatMap((m) => m.items.flatMap((i) => i.risks.map((r) => r.id))),
);
const after = withModel.modules.flatMap((m) => m.items.flatMap((i) => i.risks));
const added = after.filter((r) => !before.has(r.id));

console.log(`${withModel.stats.proposalsMade} suggestions in ${elapsed}s`);
console.log(`  verified as real:   ${withModel.stats.proposalsConfirmed}`);
console.log(`  rejected by rules:  ${withModel.unverified.length}`);
console.log(`  NEW findings the rules missed alone: ${added.length}`);

for (const r of added) console.log(`     [${r.grade.toUpperCase()}] ${r.what.slice(0, 150)}`);

console.log(`\nrejected suggestions and why:`);
for (const u of withModel.unverified) {
  console.log(`  ${u.door}: ${u.whyNotShown}`);
}
