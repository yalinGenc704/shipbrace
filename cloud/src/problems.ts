import type { ReviewProblem } from "@shipbrace/server/github/webhook.ts";

/** A week: long enough to see on the dashboard, short enough to hold nothing for long. */
const KEEP_DAYS = 7;
/** Fixed text from ShipBrace itself; capped all the same. */
const MAX_TEXT = 1_000;

/** Kept so the dashboard can say why a review stopped (see migrations/0009). */
export async function recordProblem(db: D1Database, problem: ReviewProblem): Promise<void> {
  await db
    .prepare(
      `INSERT INTO review_problems (github_id, installation_id, ran_by, commit_sha, title, message)
       VALUES (?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      problem.githubId,
      problem.installationId,
      problem.ranBy ?? null,
      problem.commitSha,
      problem.title.slice(0, MAX_TEXT),
      problem.message.slice(0, MAX_TEXT),
    )
    .run();
}

export const forgetOldProblems = (db: D1Database) =>
  db.prepare("DELETE FROM review_problems WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)").bind(`-${KEEP_DAYS} days`);
