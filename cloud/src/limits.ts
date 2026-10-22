/**
 * The ceiling on what reviews can cost. A review is counted when it starts,
 * before its container runs, so ones that time out, crash, or are too large
 * to keep count as much as ones that finish.
 *
 * Three limits:
 * - per GitHub account (one installation of the App), per calendar month
 *   (UTC), resetting on the 1st: MONTHLY_REVIEW_LIMIT. Every review of that
 *   account's repositories counts, pushed or pasted, whoever started it.
 * - per GitHub account over the last 24 hours: ACCOUNT_DAILY_REVIEW_LIMIT,
 *   so one account cannot use up the day for everyone else.
 * - across everyone, over the last 24 hours: DAILY_REVIEW_LIMIT. A safety
 *   cap so a bug or a flood cannot run up a day's bill.
 */

const LAST_DAY = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')";
const MONTH_START = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now', 'start of month')";

export interface ReviewLimits {
  /** Reviews per GitHub account per calendar month. */
  monthly: number;
  /** Reviews per GitHub account in any 24 hours. */
  accountDaily: number;
  /** Reviews across everyone in any 24 hours. */
  daily: number;
}

export type StartRefusal = "monthly-limit" | "account-daily-limit" | "limit";

/**
 * Records a start for this installation if both limits allow one; otherwise
 * says which limit stopped it. Checking and recording are one statement, so
 * two reviews starting at once cannot both take the last place.
 */
export async function claimReviewStart(
  db: D1Database,
  installationId: number,
  limits: ReviewLimits,
): Promise<{ ok: true } | { ok: false; reason: StartRefusal }> {
  const result = await db
    .prepare(
      `INSERT INTO review_starts (installation_id)
       SELECT ?
       WHERE (SELECT count(*) FROM review_starts WHERE started_at > ${LAST_DAY}) < ?
         AND (SELECT count(*) FROM review_starts WHERE installation_id = ? AND started_at >= ${MONTH_START}) < ?
         AND (SELECT count(*) FROM review_starts WHERE installation_id = ? AND started_at > ${LAST_DAY}) < ?`,
    )
    .bind(installationId, limits.daily, installationId, limits.monthly, installationId, limits.accountDaily)
    .run();
  if ((result.meta.changes ?? 0) > 0) return { ok: true };
  // Refused: say which one, so the check can tell the account plainly.
  if ((await usedThisMonth(db, installationId)) >= limits.monthly) return { ok: false, reason: "monthly-limit" };
  const today = await db
    .prepare(`SELECT count(*) AS n FROM review_starts WHERE installation_id = ? AND started_at > ${LAST_DAY}`)
    .bind(installationId)
    .first<{ n: number }>();
  return { ok: false, reason: (today?.n ?? 0) >= limits.accountDaily ? "account-daily-limit" : "limit" };
}

/** Reviews this installation has started since the 1st of this month (UTC). */
export async function usedThisMonth(db: D1Database, installationId: number): Promise<number> {
  const row = await db
    .prepare(`SELECT count(*) AS n FROM review_starts WHERE installation_id = ? AND started_at >= ${MONTH_START}`)
    .bind(installationId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

/** For the nightly clean-up: starts from before last month are no longer needed. */
export function forgetOldStarts(db: D1Database): D1PreparedStatement {
  // 'start of month' first: "now minus a month" on the 31st can land in the wrong month.
  return db.prepare(`DELETE FROM review_starts WHERE started_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', 'start of month', '-1 month')`);
}

/** The limits as configured; a missing or unreadable setting falls back to a low default. */
export function reviewLimits(
  env: { MONTHLY_REVIEW_LIMIT?: string; ACCOUNT_DAILY_REVIEW_LIMIT?: string; DAILY_REVIEW_LIMIT?: string },
): ReviewLimits {
  const read = (value: string | undefined, fallback: number) => {
    const n = Number(value);
    return Number.isSafeInteger(n) && n >= 0 && value?.trim() ? n : fallback;
  };
  return {
    monthly: read(env.MONTHLY_REVIEW_LIMIT, 50),
    accountDaily: read(env.ACCOUNT_DAILY_REVIEW_LIMIT, 10),
    daily: read(env.DAILY_REVIEW_LIMIT, 50),
  };
}

/** The first moment of next month (UTC), for "resets on". */
export function nextReset(now = new Date()): string {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1)).toISOString();
}
