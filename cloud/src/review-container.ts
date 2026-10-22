import type { RepoSnapshot, ReviewResult } from "@shipbrace/guardrails";
import { OSV_NOTICE } from "@shipbrace/guardrails/vulnerabilities";
import type { ReviewReply, ReviewRequest } from "@shipbrace/server/sandbox/reviewer-http.ts";
import { ReviewStoppedError } from "@shipbrace/server/sandbox/stopped.ts";
import { installationSwitches } from "./accounts.ts";
import type { Env } from "./env.ts";
import type { OutsideStep } from "./outside-steps.ts";
import { aiAllowedFor } from "./ai-access.ts";
import { claimReviewStart, reviewLimits } from "./limits.ts";

const STOP_REASONS = new Set(["time", "memory", "crash", "busy", "unavailable"]);

/**
 * One review in its own container, which is destroyed afterwards.
 *
 * Counted as it starts, against a daily limit across everyone and one per
 * installation (limits.ts): a ceiling on what any burst -- or abuse -- can
 * cost. Over either, nothing runs and the check says so in plain words.
 */
export async function reviewInContainer(
  env: Env,
  snapshot: RepoSnapshot,
  installationId: number,
  ranBy?: number,
): Promise<ReviewResult> {
  const claimed = await claimReviewStart(env.DB, installationId, reviewLimits(env));
  if (!claimed.ok) {
    // The daily one is ShipBrace-wide, so it is worth noticing in the logs.
    console.error(`${claimed.reason === "limit" ? "daily safety limit" : "monthly account limit"} reached; review not started (installation ${installationId})`);
    throw new ReviewStoppedError(claimed.reason);
  }
  // Each outside step needs both: offered on this deployment, and switched on
  // for this installation. Switched off, the report says it was not checked.
  const switches = await installationSwitches(env.DB, installationId);
  // The AI step: offered, switched on for this installation, and started by
  // someone allowed to use it (ai-access.ts).
  const useAi = aiAllowedFor(env, ranBy) && switches.aiReview;
  const useLookup = env.PACKAGE_LOOKUP === "on" && switches.packageLookup;
  const reviewer = env.REVIEWER.get(env.REVIEWER.newUniqueId());
  const request: ReviewRequest = {
    files: snapshot.files.map(({ path, content }) => ({ path, content })),
    tracked: [...snapshot.tracked],
    ...(useAi ? { proposer: { name: "claude" } } : {}),
    ...(useLookup ? { vulnerabilities: { notice: OSV_NOTICE } } : {}),
  };
  // Told to the review's own record before it starts, so the Worker refuses
  // any other step even if the code inside the container is taken over.
  const allowed: OutsideStep[] = [...(useAi ? (["propose"] as const) : []), ...(useLookup ? (["lookup"] as const) : [])];

  try {
    let response: Response;
    try {
      await reviewer.allow(allowed);
      response = await reviewer.fetch("http://reviewer/review", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
    } catch (error) {
      console.error("reviewer container could not be reached:", error);
      throw new ReviewStoppedError("unavailable");
    }
    // The container reads hostile code; what it says is checked, not trusted.
    const reply = (await response.json().catch(() => null)) as ReviewReply | null;
    if (reply?.type === "done" && isReviewResult(reply.result)) return reply.result;
    if (reply?.type === "stopped" && STOP_REASONS.has(reply.reason)) throw new ReviewStoppedError(reply.reason as never);
    throw new ReviewStoppedError("crash");
  } finally {
    await reviewer.destroy().catch(() => {});
  }
}

function isReviewResult(value: unknown): value is ReviewResult {
  const r = value as ReviewResult;
  return typeof r === "object" && r !== null && Array.isArray(r.modules) && typeof r.summary === "object" && typeof r.stats === "object";
}
