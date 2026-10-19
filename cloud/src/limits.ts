/**
 * The ceiling on what reviews can cost. A review is counted when it starts,
 * before its container runs, so ones that time out, crash, or are too large
 * to keep count as much as ones that finish.
 *
 * Two limits over the last 24 hours: across everyone (DAILY_REVIEW_LIMIT) and
 * per installation (INSTALLATION_DAILY_LIMIT), so one account cannot use up
 * the day for everyone else.
 */

const SINCE = "strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')";

export interface DailyLimits {
  total: number;
  perInstallation: number;
}

/**
 * Records a start for this installation if both limits allow one. False means
 * the review must not run. Checking and recording are one statement, so two
 * reviews starting at once cannot both take the last place.
 */
export async function claimReviewStart(db: D1Database, installationId: number, limits: DailyLimits): Promise<boolean> {
  const result = await db
    .prepare(
      `INSERT INTO review_starts (installation_id)
       SELECT ?
       WHERE (SELECT count(*) FROM review_starts WHERE started_at > ${SINCE}) < ?
         AND (SELECT count(*) FROM review_starts WHERE installation_id = ? AND started_at > ${SINCE}) < ?`,
    )
    .bind(installationId, limits.total, installationId, limits.perInstallation)
    .run();
  return (result.meta.changes ?? 0) > 0;
}

/** For the nightly clean-up: starts older than a day no longer count. */
export function forgetOldStarts(db: D1Database): D1PreparedStatement {
  return db.prepare(`DELETE FROM review_starts WHERE started_at < ${SINCE}`);
}

/** The limits as configured; a missing or unreadable setting falls back to a low default. */
export function dailyLimits(env: { DAILY_REVIEW_LIMIT?: string; INSTALLATION_DAILY_LIMIT?: string }): DailyLimits {
  const read = (value: string | undefined, fallback: number) => {
    const n = Number(value);
    return Number.isSafeInteger(n) && n >= 0 && value?.trim() ? n : fallback;
  };
  return { total: read(env.DAILY_REVIEW_LIMIT, 20), perInstallation: read(env.INSTALLATION_DAILY_LIMIT, 10) };
}
