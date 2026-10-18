import { buildInventoryFromAst } from "../src/analysis/inventory-ast.ts";
import type { Inventory } from "../src/analysis/inventory.ts";
import type { AttackProposal } from "../src/analysis/oracle.ts";
import { ProposerRefusedError, type AttackProposer } from "../src/analysis/proposer.ts";
import { verifyClaim, verifyOwnership } from "../src/analysis/verify.ts";
import type { Risk } from "../src/review/modules.ts";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";
import type { BenchCase, KeyEntry } from "./cases.ts";

/**
 * Grades the review against the answer key.
 *
 * It runs the real pipeline -- the same one a user's repository goes through --
 * so what is measured is what a user would see, not what one component would
 * say in isolation. A risk counts only if it points at a dangerous line; the
 * review's other checks (missing sign-in, headers) are outside this benchmark.
 *
 * Three ways of running it:
 *   rules     - no model at all. The floor.
 *   perfect   - a scripted suggester that names every marked line, real and
 *               safe, plus some plainly wrong claims. This is the ceiling: what
 *               the checker can confirm when the suggestions are as good as
 *               they can be. The gap between it and the real model is the
 *               model's fault; the gap between it and 100% is the checker's.
 *   model     - a real model, when one is supplied.
 */

export type Mode = "rules" | "perfect" | "model";

export interface Outcome {
  caseId: string;
  entry: KeyEntry;
  /** True when the review reported a risk on this line. */
  reported: boolean;
  /**
   * How the reported risk was established: `oracle` traced the visitor's value
   * to this line; `rule` only saw that the line is built unsafely. Kept apart
   * because only the first is proof.
   */
  by?: Risk["confirmedBy"];
  /**
   * True when the line appears in the "worth a look, not proven" list instead.
   * A lead on a real problem is better than nothing; a lead on safe code costs
   * the user a look but is not a false alarm, because it never claims a risk.
   */
  lead?: boolean;
  /** For a miss: why, in words a reader can act on. */
  explanation?: string;
  /** In model mode: whether the model suggested this line at all. */
  suggested?: boolean;
}

export interface Unexpected {
  caseId: string;
  risk: Pick<Risk, "id" | "what">;
}

export interface Score {
  mode: Mode;
  real: { total: number; found: number; proven: number; leads: number };
  safe: { total: number; cleared: number; leads: number };
  outcomes: Outcome[];
  /** Risks on lines the key does not mark. Counted as false alarms. */
  unexpected: Unexpected[];
  proposals: { made: number; confirmed: number };
  /** Cases where the model declined, with its stated reason. */
  refusals: Array<{ caseId: string; reason: string }>;
}

/** Lines carrying each `// [X]` marker, so the key can name lines without numbers. */
function markerLines(benchCase: BenchCase): Map<string, { path: string; line: number }> {
  const found = new Map<string, { path: string; line: number }>();

  for (const f of benchCase.files) {
    f.content.split("\n").forEach((text, index) => {
      for (const match of text.matchAll(/\/\/ \[([A-Z])\]/g)) {
        const marker = match[1]!;
        if (found.has(marker)) throw new Error(`${benchCase.id}: marker [${marker}] used twice`);
        found.set(marker, { path: f.path, line: index + 1 });
      }
    });
  }
  for (const entry of benchCase.key) {
    if (!found.has(entry.marker)) {
      throw new Error(`${benchCase.id}: key names [${entry.marker}] but no line carries it`);
    }
  }
  return found;
}

/** Risks that point at a dangerous operation, as opposed to project-level advice. */
const isAboutAnOperation = (risk: Risk, inventory: Inventory): boolean =>
  risk.id.startsWith("taint/") ||
  risk.id.startsWith("injection/") ||
  inventory.sinks.some(
    (s) => s.location.path === risk.location?.path && s.location.line === risk.location?.line,
  );

/** Says every marked line, real or not, and the wrong claims too. */
function perfectSuggester(benchCase: BenchCase): AttackProposer {
  const claims = [
    ...benchCase.key.map(({ door, parameter, sink }) => ({ door, parameter, sink })),
    ...(benchCase.wrongClaims ?? []),
  ];
  return {
    name: "perfect",
    propose: () =>
      Promise.resolve(
        claims.map((c): AttackProposal => ({
          door: c.door ?? "",
          parameter: c.parameter,
          payload: "",
          expectedSink: c.sink,
          rationale: "scripted",
        })),
      ),
  };
}

/** Wraps a real proposer to remember what it said, so a miss can be attributed. */
/**
 * Wraps a real proposer to remember what it said, so a miss can be attributed.
 *
 * A refusal is recorded rather than thrown: whether the model declines on
 * vulnerable code is one of the things this benchmark exists to measure. Any
 * other failure (network, credit) still stops the run, so a broken run is
 * never mistaken for a model that found nothing.
 */
function recording(
  inner: AttackProposer,
): { proposer: AttackProposer; said: AttackProposal[]; refusals: string[] } {
  const said: AttackProposal[] = [];
  const refusals: string[] = [];
  return {
    said,
    refusals,
    proposer: {
      name: inner.name,
      propose: async (context) => {
        try {
          const proposals = await inner.propose(context);
          said.push(...proposals);
          return proposals;
        } catch (error) {
          if (error instanceof ProposerRefusedError) {
            refusals.push(error.message);
            return [];
          }
          throw error;
        }
      },
    },
  };
}

function explainMiss(entry: KeyEntry, at: { path: string; line: number }, inventory: Inventory) {
  const recognised = inventory.sinks.some(
    (s) => s.location.path === at.path && s.location.line === at.line,
  );
  if (!recognised && entry.sink !== "ownership") {
    return `the tool does not recognise line ${at.line} as a risky ${entry.sink} operation`;
  }
  const verdict = entry.sink === "ownership"
    ? verifyOwnership({ door: entry.door ?? "", parameter: entry.parameter }, inventory)
    : verifyClaim(
      { ...(entry.door ? { door: entry.door } : {}), parameter: entry.parameter, sink: entry.sink },
      inventory,
    );
  if (verdict.verdict === "valid") {
    return entry.sink === "ownership"
      ? "only an AI suggests this kind of problem; the checker confirms it when asked"
      : "nothing suggested this line; the checker confirms it when asked";
  }
  return `checker said "${verdict.verdict}": ${verdict.reason}`;
}

async function gradeCase(
  benchCase: BenchCase,
  mode: Mode,
  model?: AttackProposer,
): Promise<Omit<Score, "mode">> {
  const lines = markerLines(benchCase);
  const snapshot = snapshotFromFiles(benchCase.files);
  const inventory = buildInventoryFromAst(snapshot);

  const recorder = mode === "model" && model ? recording(model) : undefined;
  const proposer = mode === "perfect"
    ? perfectSuggester(benchCase)
    : recorder?.proposer;

  const review = await runSecurityReview(snapshot, proposer ? { proposer } : {});
  const risks = review.modules
    .flatMap((m) => m.items.flatMap((i) => i.risks))
    .filter((r) => isAboutAnOperation(r, inventory));
  const leads = review.modules.flatMap((m) => m.items.flatMap((i) => i.unproven));

  const at = (r: { location?: Risk["location"] }, where: { path: string; line: number }) =>
    r.location?.path === where.path && r.location?.line === where.line;

  const outcomes: Outcome[] = benchCase.key.map((entry) => {
    const where = lines.get(entry.marker)!;
    const hit = risks.find((r) => at(r, where));
    const reported = Boolean(hit);
    const outcome: Outcome = {
      caseId: benchCase.id,
      entry,
      reported,
      ...(hit ? { by: hit.confirmedBy } : {}),
      ...(!hit && leads.some((l) => at(l, where)) ? { lead: true } : {}),
    };

    if (entry.real && !reported) outcome.explanation = explainMiss(entry, where, inventory);
    if (!entry.real && reported) {
      outcome.explanation = hit!.what;
    }
    if (recorder) {
      outcome.suggested = recorder.said.some(
        (p) => p.expectedSink === entry.sink && (!entry.door || p.door === entry.door),
      );
    }
    return outcome;
  });

  const marked = [...lines.values()];
  const unexpected = risks
    .filter((r) => !marked.some((where) => at(r, where)))
    .map((r) => ({ caseId: benchCase.id, risk: { id: r.id, what: r.what } }));

  return {
    real: {
      total: outcomes.filter((o) => o.entry.real).length,
      found: outcomes.filter((o) => o.entry.real && o.reported).length,
      proven: outcomes.filter((o) => o.entry.real && o.by === "oracle").length,
      leads: outcomes.filter((o) => o.entry.real && o.lead).length,
    },
    safe: {
      total: outcomes.filter((o) => !o.entry.real).length,
      cleared: outcomes.filter((o) => !o.entry.real && !o.reported).length,
      leads: outcomes.filter((o) => !o.entry.real && o.lead).length,
    },
    outcomes,
    unexpected,
    proposals: { made: review.stats.proposalsMade, confirmed: review.stats.proposalsConfirmed },
    refusals: (recorder?.refusals ?? []).map((reason) => ({ caseId: benchCase.id, reason })),
  };
}

export async function grade(
  cases: BenchCase[],
  mode: Mode,
  model?: AttackProposer,
): Promise<Score> {
  const score: Score = {
    mode,
    real: { total: 0, found: 0, proven: 0, leads: 0 },
    safe: { total: 0, cleared: 0, leads: 0 },
    outcomes: [],
    unexpected: [],
    proposals: { made: 0, confirmed: 0 },
    refusals: [],
  };

  for (const benchCase of cases) {
    const result = await gradeCase(benchCase, mode, model);
    score.real.total += result.real.total;
    score.real.found += result.real.found;
    score.real.proven += result.real.proven;
    score.real.leads += result.real.leads;
    score.safe.leads += result.safe.leads;
    score.safe.total += result.safe.total;
    score.safe.cleared += result.safe.cleared;
    score.outcomes.push(...result.outcomes);
    score.unexpected.push(...result.unexpected);
    score.proposals.made += result.proposals.made;
    score.proposals.confirmed += result.proposals.confirmed;
    score.refusals.push(...result.refusals);
  }
  return score;
}

/** False alarms of both kinds: a safe line reported, or an unmarked line reported. */
export const falseAlarms = (score: Score): number =>
  score.safe.total - score.safe.cleared + score.unexpected.length;
