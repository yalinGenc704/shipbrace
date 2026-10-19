import type { RepoSnapshot, ReviewResult } from "@shipbrace/guardrails";
import { OSV_NOTICE } from "@shipbrace/guardrails/vulnerabilities";
import type { ReviewReply, ReviewRequest } from "@shipbrace/server/sandbox/reviewer-http.ts";
import { ReviewStoppedError } from "@shipbrace/server/sandbox/stopped.ts";
import { installationSwitches } from "./accounts.ts";
import type { Env } from "./env.ts";
import { claimReviewStart, dailyLimits } from "./limits.ts";

const STOP_REASONS = new Set(["time", "memory", "crash", "busy", "unavailable"]);

/**
 * One review in its own container, which is destroyed afterwards.
 *
 * Counted as it starts, against a daily limit across everyone and one per
 * installation (limits.ts): a ceiling on what any burst -- or abuse -- can
 * cost. Over either, nothing runs and the check says so in plain words.
 */
export async function reviewInContainer(env: Env, snapshot: RepoSnapshot, installationId: number): Promise<ReviewResult> {
  if (!(await claimReviewStart(env.DB, installationId, dailyLimits(env)))) {
    console.error(`daily review limit reached; review not started (installation ${installationId})`);
    throw new ReviewStoppedError("limit");
  }
  // Each outside step needs both: offered on this deployment, and switched on
  // for this installation. Switched off, the report says it was not checked.
  const switches = await installationSwitches(env.DB, installationId);
  const reviewer = env.REVIEWER.get(env.REVIEWER.newUniqueId());
  const request: ReviewRequest = {
    files: snapshot.files.map(({ path, content }) => ({ path, content })),
    tracked: [...snapshot.tracked],
    ...(env.AI_REVIEW === "on" && env.ANTHROPIC_API_KEY && switches.aiReview ? { proposer: { name: "claude" } } : {}),
    ...(env.PACKAGE_LOOKUP === "on" && switches.packageLookup ? { vulnerabilities: { notice: OSV_NOTICE } } : {}),
  };

  try {
    let response: Response;
    try {
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
