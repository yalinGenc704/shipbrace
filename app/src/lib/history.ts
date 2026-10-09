import type { ReviewResult } from "@aegis/guardrails";

/**
 * Past reviews kept by the server (server/src/history.ts), read back by the
 * addresses the GitHub check links to.
 *
 * Unlike the live review there is no fixture to fall back to: showing sample
 * data at the address of a real repository's review would be a made-up
 * result, so a failure is shown as one.
 */

export type Conclusion = "success" | "neutral" | "failure";

export interface ReviewEntry {
  id: string;
  commitSha: string;
  createdAt: string;
  conclusion: Conclusion;
  title: string;
  counts: { high: number; medium: number; low: number; awaitingReview: number; unproven: number };
}

export interface StoredReview extends ReviewEntry {
  repository: { owner: string; name: string; historyId: string };
  result: ReviewResult;
  skipped: { notReadable: number; tooLarge: number; overLimit: number; treeTruncated: boolean };
}

export interface RepositoryHistory {
  owner: string;
  name: string;
  reviews: ReviewEntry[];
}

/** "Not found" is its own answer: the page words it differently from an outage. */
export class NotFound extends Error {}

async function get<T>(path: string): Promise<T> {
  const response = await fetch(path);
  if (response.status === 404) throw new NotFound();
  if (!response.ok) throw new Error(`The server answered ${response.status}.`);
  return (await response.json()) as T;
}

export const loadStoredReview = (id: string) => get<StoredReview>(`/api/reviews/${encodeURIComponent(id)}`);
export const loadHistory = (id: string) => get<RepositoryHistory>(`/api/history/${encodeURIComponent(id)}`);

export function formatWhen(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}
