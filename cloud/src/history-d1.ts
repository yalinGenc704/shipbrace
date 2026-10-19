import type { ReviewResult } from "@shipbrace/guardrails";
import type { Conclusion } from "@shipbrace/server/github/report.ts";
import type { ReviewEntry, ReviewHistory, Skipped } from "@shipbrace/server/history.ts";
import { LINK_ID, newLinkId } from "@shipbrace/server/links.ts";

/**
 * Review history on Cloudflare D1, behaving exactly like the PostgreSQL one in
 * server/src/history.ts: written once per reviewed push, read back only by
 * unguessable link. D1 keeps 30 days of point-in-time history on its own.
 *
 * Every value goes in as a bound parameter (`?`), never into the query text.
 */

/** D1 refuses rows over 2 MB. A larger review is not kept; the check still posts in full. */
const MAX_RESULT_BYTES = 1_900_000;
const HISTORY_LIMIT = 100;

interface ReviewRow {
  id: string;
  commit_sha: string;
  created_at: string;
  conclusion: Conclusion;
  title: string;
  high: number;
  medium: number;
  low: number;
  awaiting: number;
  unproven: number;
}

const entry = (row: ReviewRow): ReviewEntry => ({
  id: row.id,
  commitSha: row.commit_sha,
  createdAt: row.created_at,
  conclusion: row.conclusion,
  title: row.title,
  counts: {
    high: row.high,
    medium: row.medium,
    low: row.low,
    awaitingReview: row.awaiting,
    unproven: row.unproven,
  },
});

/** `repository` takes an extra filter here: only the reviews one person started. */
export function d1History(db: D1Database): ReviewHistory & { repository(historyId: string, ranBy?: number): ReturnType<ReviewHistory["repository"]> } {
  return {
    async record(review) {
      const result = JSON.stringify(review.result);
      if (new TextEncoder().encode(result).length > MAX_RESULT_BYTES) {
        throw new Error("review too large to keep in the history");
      }
      const { high, medium, low, awaitingReview, unproven } = review.result.summary;

      // The name is refreshed on every push, so a renamed repository keeps
      // its history and its link under the new name.
      const repository = await db
        .prepare(
          `INSERT INTO repositories (github_id, owner, name, history_id, installation_id) VALUES (?, ?, ?, ?, ?)
           ON CONFLICT (github_id) DO UPDATE SET owner = excluded.owner, name = excluded.name,
             installation_id = coalesce(excluded.installation_id, repositories.installation_id)
           RETURNING id, history_id`,
        )
        .bind(review.githubId, review.owner, review.repo, newLinkId(), review.installationId ?? null)
        .first<{ id: number; history_id: string }>();
      if (!repository) throw new Error("repository row was not written");

      const reviewId = newLinkId();
      await db
        .prepare(
          `INSERT INTO reviews (id, repository_id, commit_sha, conclusion, title,
                                high, medium, low, awaiting, unproven, result, skipped, ran_by)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          reviewId, repository.id, review.commitSha, review.conclusion, review.title,
          high, medium, low, awaitingReview, unproven, result, JSON.stringify(review.skipped), review.ranBy ?? null,
        )
        .run();
      return { reviewId, historyId: repository.history_id };
    },

    async review(id) {
      if (!LINK_ID.test(id)) return null;
      const row = await db
        .prepare(
          `SELECT r.*, p.owner, p.name, p.history_id
           FROM reviews r JOIN repositories p ON p.id = r.repository_id
           WHERE r.id = ?`,
        )
        .bind(id)
        .first<ReviewRow & { result: string; skipped: string; owner: string; name: string; history_id: string }>();
      if (!row) return null;
      return {
        ...entry(row),
        repository: { owner: row.owner, name: row.name, historyId: row.history_id },
        result: JSON.parse(row.result) as ReviewResult,
        skipped: JSON.parse(row.skipped) as Skipped,
      };
    },

    async repository(historyId: string, ranBy?: number) {
      if (!LINK_ID.test(historyId)) return null;
      const repository = await db
        .prepare("SELECT id, owner, name FROM repositories WHERE history_id = ?")
        .bind(historyId)
        .first<{ id: number; owner: string; name: string }>();
      if (!repository) return null;
      const { results } = await db
        .prepare(
          `SELECT id, commit_sha, created_at, conclusion, title, high, medium, low, awaiting, unproven
           FROM reviews WHERE repository_id = ? AND (? IS NULL OR ran_by = ?)
           ORDER BY created_at DESC, id LIMIT ?`,
        )
        .bind(repository.id, ranBy ?? null, ranBy ?? null, HISTORY_LIMIT)
        .all<ReviewRow>();
      return { owner: repository.owner, name: repository.name, reviews: results.map(entry) };
    },

    close: async () => {},
  };
}
