import type { ReviewResult } from "@aegis/guardrails";
import fixture from "../fixtures/review.json";

/**
 * Where the dashboard gets a review from.
 *
 * Today it is a fixture generated from the real engine (`npm run fixture`).
 * When the server exists this becomes a fetch against it; the component tree
 * does not change, because it only ever sees a `ReviewResult`.
 */
export async function loadReview(): Promise<ReviewResult> {
  const response = await fetch("/api/review").catch(() => null);

  if (response?.ok) return (await response.json()) as ReviewResult;

  // The fixture is real engine output, so the shape is guaranteed to match.
  return fixture as unknown as ReviewResult;
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
