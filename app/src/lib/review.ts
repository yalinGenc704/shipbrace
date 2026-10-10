import type { ReviewResult } from "@shipbrace/guardrails";

/**
 * The front page's review: a review of a folder on the machine the server runs
 * on (laptop use). A hosted server has no such review and answers 404; the
 * page then explains where reports come from instead (`null`).
 *
 * The sample review (`npm run fixture`) appears only while developing the
 * dashboard with no server running. In a real deployment, sample data on the
 * front page would read as somebody's actual result.
 */
export async function loadReview(): Promise<ReviewResult | null> {
  const response = await fetch("/api/review").catch(() => null);

  if (response?.ok) return (await response.json()) as ReviewResult;
  // No folder review here (hosted): show the home page. 401 is the same
  // answer from a server that asks everyone to sign in first.
  if ((response?.status === 404 || response?.status === 401) && !import.meta.env.DEV) return null;

  if (import.meta.env.DEV) {
    // Real engine output, so the shape is guaranteed to match.
    const fixture = await import("../fixtures/review.json");
    return fixture.default as unknown as ReviewResult;
  }
  throw new Error(`The server answered ${response?.status ?? "nothing"}.`);
}

export type Mode = "essentials" | "detailed";

/**
 * The two views of one finding set, matching the engine's own split.
 *
 * `essentials` is for someone who chose to stay out of the code: plain language,
 * no paths, no excerpts. `detailed` adds the location, the traced path, and
 * which detector fired, for someone following along.
 *
 * They are the same risks either way -- detailed mode never reveals a problem
 * essentials mode hid, or the safe-by-default promise would be false for the
 * people relying on it most.
 */
export const MODE_LABEL: Record<Mode, string> = {
  essentials: "Just what I need to do",
  detailed: "Show me the code",
};
