import { buildInventoryFromAst as buildInventory } from "../analysis/inventory-ast.ts";
import {
  analyseTaint,
  type ConfirmedAttack,
  type TaintPath,
  type Verdict,
} from "../analysis/oracle.ts";
import {
  verifyClaim,
  verifyOwnership,
  type Claim,
  type ClaimVerdict,
} from "../analysis/verify.ts";
import type { Inventory } from "../analysis/inventory.ts";
import { nullProposer, type AttackProposer } from "../analysis/proposer.ts";
import { scan } from "../engine.ts";
import type { RepoSnapshot } from "../types.ts";
import { isTestPath, redact } from "../util.ts";
import { runProjectChecks } from "./checks.ts";
import { checkKnownVulnerabilities, type VulnerabilitySource } from "./vulnerabilities.ts";
import { buildReview, type OwnershipGap, type SecurityReview } from "./modules.ts";

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
  /**
   * Where to look up known flaws in installed packages. Defaults to none: the
   * library never contacts anything outside on its own. The server opts in.
   */
  vulnerabilities?: VulnerabilitySource;
}

export interface ReviewResult extends SecurityReview {
  stats: {
    doors: number;
    sources: number;
    sinks: number;
    exploitablePaths: number;
    /** Paths confirmed by pairing every input with every operation. */
    pairedConfirmed: number;
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

  /**
   * The rules' own suggestions: every input paired with every kind of
   * operation, each decided by the same verifier a model's suggestion faces.
   *
   * The all-paths pass stays inside one route handler; the verifier follows a
   * value into other functions and files. So pairing finds what enumeration
   * misses, without a model, a key, or any cost -- and it cannot invent a
   * finding, because only `valid` counts and the verifier never consults
   * anything but the code.
   */
  let pairedConfirmed = 0;
  for (const claim of pairingClaims(inventory)) {
    const result = verifyClaim(claim, inventory);
    if (result.verdict !== "valid" || !result.source || !result.sink) continue;
    const path = pathFrom(result);
    if (paths.some((existing) => existing.id === path.id)) continue;
    paths.push(path);
    pairedConfirmed++;
  }

  const proposer = options.proposer ?? nullProposer;
  let proposalsMade = 0;
  const confirmed: ConfirmedAttack[] = [];
  const unverified: ConfirmedAttack[] = [];
  const ownership: OwnershipGap[] = [];

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
      /**
       * "One user can reach another's record" is decided by its own rules:
       * the route requires signing in, the input reaches a query, and nothing
       * on the way asks who is signed in. The model chose where to look; the
       * rules decide what is there.
       */
      if (proposal.expectedSink === "ownership") {
        const result = verifyOwnership(
          { door: proposal.door, parameter: proposal.parameter, origin: proposal.rationale },
          inventory,
        );
        if (result.verdict === "valid" && result.door && result.source && result.sink) {
          if (!ownership.some((o) => o.door.id === result.door!.id && o.sink.id === result.sink!.id)) {
            ownership.push({ door: result.door, source: result.source, sink: result.sink, via: result.via ?? [] });
          }
          confirmed.push({ proposal, verdict: "exploitable" });
        } else {
          unverified.push({ proposal, verdict: VERDICT_MAP[result.verdict] });
        }
        continue;
      }

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
        const path = pathFrom(result);
        if (!paths.some((existing) => existing.id === path.id)) paths.push(path);

        confirmed.push({ proposal, verdict: "exploitable", path });
      } else {
        unverified.push({ proposal, verdict: VERDICT_MAP[result.verdict] });
      }
    }
  }

  const checks: Map<string, Awaited<ReturnType<typeof checkKnownVulnerabilities>> & { detector: string }> =
    runProjectChecks(snapshot, inventory);
  checks.set("components/known-vulnerabilities", {
    ...(await checkKnownVulnerabilities(snapshot, options.vulnerabilities)),
    detector: "osv:known-vulnerabilities",
  });
  const review = buildReview({ findings, paths, inventory, confirmed, unverified, checks, ownership });

  return {
    ...review,
    stats: {
      doors: inventory.doors.length,
      sources: inventory.sources.length,
      sinks: inventory.sinks.length,
      exploitablePaths: paths.filter((p) => p.verdict === "exploitable").length,
      pairedConfirmed,
      proposalsMade,
      proposalsConfirmed: confirmed.length,
      durationMs: performance.now() - started,
    },
  };
}

function pathFrom(result: ReturnType<typeof verifyClaim>): TaintPath {
  return {
    id: `${result.source!.id}->${result.sink!.id}`,
    verdict: "exploitable",
    source: result.source!,
    sink: result.sink!,
    ...(result.door ? { door: result.door } : {}),
    via: result.via ?? [],
    location: result.sink!.location,
  };
}

/**
 * One claim per input and kind of operation present.
 *
 * Kinds rather than individual operations, because the verifier already tries
 * every operation of the claimed kind. Cheap: a few inputs times at most seven
 * kinds, each check following one value.
 */
function pairingClaims(inventory: Inventory): Claim[] {
  const kinds = [...new Set(inventory.sinks.filter((s) => !s.inherentlySafe).map((s) => s.kind))];
  const doors = new Map(inventory.doors.map((d) => [d.id, d]));
  const claims: Claim[] = [];
  const seen = new Set<string>();

  for (const source of inventory.sources) {
    const door = source.doorId ? doors.get(source.doorId) : undefined;
    const parameter = source.binding ?? source.expression;
    for (const sink of kinds) {
      // `METHOD:/path` pins the exact route; two routes can share a path.
      const claim: Claim = {
        ...(door ? { door: `${door.method}:${door.path}` } : {}),
        parameter,
        sink,
        origin: "pairing",
      };
      const key = `${claim.door}|${parameter}|${sink}`;
      if (seen.has(key)) continue;
      seen.add(key);
      claims.push(claim);
    }
  }
  return claims;
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

/**
 * Source code only, never configuration or secrets. `.env` files, lockfiles,
 * and anything that is not code are what hold keys and passwords, and the
 * model does not need them to suggest where to look.
 */
const SENDABLE = /\.[cm]?[jt]sx?$/;

/**
 * What the model is shown: server code first -- that is where the doors are --
 * then whatever fits, every excerpt passed through `redact()` first.
 *
 * This is the one place the user's code leaves the platform, so it is the
 * boundary where secrets are removed. An earlier version sent files whole,
 * `.env` included, while a comment elsewhere claimed they were redacted.
 */
export function excerptsFor(snapshot: RepoSnapshot, budget: number): Array<{ path: string; code: string }> {
  const ranked = snapshot.files
    .filter((f) => SENDABLE.test(f.path) && !isTestPath(f.path))
    .sort((a, b) => {
      const score = (p: string) => (/(^|\/)server\//.test(p) ? 0 : 1);
      return score(a.path) - score(b.path);
    });

  const excerpts: Array<{ path: string; code: string }> = [];
  let used = 0;

  for (const file of ranked) {
    const code = redact(file.content);
    if (used + code.length > budget) continue;
    excerpts.push({ path: file.path, code });
    used += code.length;
  }
  return excerpts;
}
