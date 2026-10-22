/**
 * Who may use the AI step. It is the only part of a review with a real
 * per-review cost, so it runs only for reviews started by people listed in
 * AI_ALLOWED_GITHUB_IDS (by GitHub's permanent user id, not by name), and only
 * when the deployment offers it at all.
 */
export function aiAllowedFor(
  env: { AI_REVIEW: "on" | "off"; ANTHROPIC_API_KEY?: string; AI_ALLOWED_GITHUB_IDS?: string },
  githubId: number | undefined,
): boolean {
  if (env.AI_REVIEW !== "on" || !env.ANTHROPIC_API_KEY || githubId === undefined) return false;
  return (env.AI_ALLOWED_GITHUB_IDS ?? "")
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .includes(String(githubId));
}
