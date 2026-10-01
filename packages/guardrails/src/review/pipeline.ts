import { buildInventoryFromAst as buildInventory } from "../analysis/inventory-ast.ts";
import {
  analyseTaint,
  type ConfirmedAttack,
  type TaintPath,
  type Verdict,
} from "../analysis/oracle.ts";
import { verifyClaim, type ClaimVerdict } from "../analysis/verify.ts";
import { nullProposer, type AttackProposer } from "../analysis/proposer.ts";
import { scan } from "../engine.ts";
import type { RepoSnapshot } from "../types.ts";
import { runProjectChecks } from "./checks.ts";
import { buildReview, type SecurityReview } from "./modules.ts";

export interface ReviewOptions {
  /**
   * Suggests ways in for the verifier to check. Defaults to none, so the review
   * runs deterministically and for free without a model configured. Adding one
   * can only ever add verified findings; it can never remove or downgrade one
   * the rules found unaided.
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
 *   1. inventory - what routes, inputs, and dangerous operations exist
 *   2. enumerate - the paths the rules can find unaided
 *   3. propose   - ways in that a model suggests trying      (optional)
 *   4. verify    - the rules decide each suggestion on its own terms
 *   5. review    - assemble the ten modules for the user
 *
 * Steps 3 and 4 are the division of labour: the search is open-ended and
 * imprecise, the check is narrow and exact. Only step 4 can create a finding,
 * and it never consults a model, so a wrong suggestion fails whether it was
 * made confidently or not.
 *
 * Step 2 runs before the model so the rules' own findings exist independently
 * of anything it says. That is what stops a hostile repository from using the
 * model to suppress a real result.
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
  const confirmed: ConfirmedAttack[] = [];
  const unverified: ConfirmedAttack[] = [];

  if (proposer !== nullProposer && inventory.doors.length > 0) {
    const proposals = await proposer.propose({
      doors: inventory.doors,
      sinks: inventory.sinks,
      excerpts: excerptsFor(snapshot, options.maxExcerptBytes ?? 60_000),
    });
    proposalsMade = proposals.length;

    /**
     * Each proposal is checked on its own terms.
     *
     * The earlier version matched proposals against paths the enumerating pass
     * had already found, which meant a proposal could never contribute
     * anything -- it was only ever recognised, never evaluated. Now the
     * verifier follows the claimed route itself, including into other
     * functions, so a proposal can establish a finding the enumeration missed.
     * It still cannot establish one on its own say-so: only `valid`, decided
     * by rules alone, becomes a finding.
     */
    for (const proposal of proposals) {
      const result = verifyClaim(
        {
          door: proposal.door,
          parameter: proposal.parameter,
          sink: proposal.expectedSink as Parameters<typeof verifyClaim>[0]["sink"],
          origin: proposal.rationale,
        },
        inventory,
      );

      if (result.verdict === "valid" && result.source && result.sink) {
        const path: TaintPath = {
          id: `${result.source.id}->${result.sink.id}`,
          verdict: "exploitable",
          source: result.source,
          sink: result.sink,
          ...(result.door ? { door: result.door } : {}),
          via: result.via ?? [],
          location: result.sink.location,
        };
        if (!paths.some((existing) => existing.id === path.id)) paths.push(path);

        confirmed.push({ proposal, verdict: "exploitable", path });
      } else {
        unverified.push({ proposal, verdict: VERDICT_MAP[result.verdict] });
      }
    }
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

/**
 * How a rejected claim is described to the user.
 *
 * "Could not follow it" and "checked it and it is fine" must stay distinct: the
 * first is a gap in the verifier, the second is a verdict. Collapsing them
 * would turn a blind spot into a reassurance.
 */
const VERDICT_MAP: Record<ClaimVerdict, Verdict> = {
  valid: "exploitable",
  blocked: "sanitized",
  "no-path": "unreachable",
  "not-found": "unreachable",
  undecidable: "indeterminate",
};

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
