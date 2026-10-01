import { buildInventory } from "../analysis/inventory.ts";
import { analyseTaint, confirmAll } from "../analysis/oracle.ts";
import { nullProposer, type AttackProposer } from "../analysis/proposer.ts";
import { scan } from "../engine.ts";
import type { RepoSnapshot } from "../types.ts";
import { runProjectChecks } from "./checks.ts";
import { buildReview, type SecurityReview } from "./modules.ts";

export interface ReviewOptions {
  /**
   * Attack simulation. Defaults to none, so the review runs -- deterministically
   * and for free -- without a model configured. Adding one can only ever add
   * confirmed findings; it can never remove or downgrade one the oracle found.
   */
  proposer?: AttackProposer;
  /** Cap on source shown to the proposer, to bound cost. */
  maxExcerptBytes?: number;
}

export interface ReviewResult extends SecurityReview {
  stats: {
    doors: number;
    sources: number;
    sinks: number;
    exploitablePaths: number;
    proposalsMade: number;
    proposalsConfirmed: number;
    durationMs: number;
  };
}

/**
 * The full review, in the order the phases depend on each other.
 *
 *   1. inventory  - what doors, inputs, and dangerous operations exist
 *   2. oracle     - which inputs reach which operations unchecked
 *   3. proposer   - what a model thinks could be attacked  (optional)
 *   4. oracle     - confirm or reject every proposal
 *   5. review     - assemble the ten modules for the user
 *
 * The oracle runs before the model and again after it. Running it first means
 * the deterministic findings exist independently of anything the model says,
 * which is what makes the model's output unable to suppress them.
 */
export async function runSecurityReview(
  snapshot: RepoSnapshot,
  options: ReviewOptions = {},
): Promise<ReviewResult> {
  const started = performance.now();

  const inventory = buildInventory(snapshot);
  const paths = analyseTaint(inventory);
  const { findings } = scan(snapshot);

  const proposer = options.proposer ?? nullProposer;
  let proposalsMade = 0;
  let confirmed: ReturnType<typeof confirmAll>["confirmed"] = [];
  let unverified: ReturnType<typeof confirmAll>["unverified"] = [];

  if (proposer !== nullProposer && inventory.doors.length > 0) {
    const proposals = await proposer.propose({
      doors: inventory.doors,
      sinks: inventory.sinks,
      excerpts: excerptsFor(snapshot, options.maxExcerptBytes ?? 60_000),
    });
    proposalsMade = proposals.length;
    ({ confirmed, unverified } = confirmAll(proposals, paths));
  }

  const checks = runProjectChecks(snapshot, inventory);
  const review = buildReview({ findings, paths, inventory, confirmed, unverified, checks });

  return {
    ...review,
    stats: {
      doors: inventory.doors.length,
      sources: inventory.sources.length,
      sinks: inventory.sinks.length,
      exploitablePaths: paths.filter((p) => p.verdict === "exploitable").length,
      proposalsMade,
      proposalsConfirmed: confirmed.length,
      durationMs: performance.now() - started,
    },
  };
}

/** Server code first -- that is where the doors are -- then whatever fits. */
function excerptsFor(snapshot: RepoSnapshot, budget: number): Array<{ path: string; code: string }> {
  const ranked = [...snapshot.files].sort((a, b) => {
    const score = (p: string) => (/(^|\/)server\//.test(p) ? 0 : 1);
    return score(a.path) - score(b.path);
  });

  const excerpts: Array<{ path: string; code: string }> = [];
  let used = 0;

  for (const file of ranked) {
    if (used + file.content.length > budget) continue;
    excerpts.push({ path: file.path, code: file.content });
    used += file.content.length;
  }
  return excerpts;
}
