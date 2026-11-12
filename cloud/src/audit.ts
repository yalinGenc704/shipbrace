/**
 * A record of who did what and when, for actions that change who can do what
 * or what leaves the platform. Written only; nothing in the app reads it back
 * or offers a way to change it.
 */

export type AuditAction =
  | "sign-in"
  | "sign-out"
  | "notices-accepted"
  | "installation-set-up"
  | "switches-changed"
  | "installation-removed"
  | "repositories-removed"
  | "push-reviews-changed"
  | "history-cleared"
  | "account-deleted"
  | "refused";

export const KEEP_AUDIT_DAYS = 365;

/**
 * Adds one entry. A failure is logged, not thrown: the action itself has
 * already been checked and done, and refusing it now would not undo it.
 * `detail` holds names and settings only -- never a token, cookie or code.
 */
export async function record(
  db: D1Database,
  entry: { actor?: number; action: AuditAction; target?: string | number; detail?: Record<string, unknown> },
): Promise<void> {
  try {
    await db
      .prepare("INSERT INTO audit_log (actor, action, target, detail) VALUES (?, ?, ?, ?)")
      .bind(entry.actor ?? null, entry.action, entry.target === undefined ? null : String(entry.target), entry.detail ? JSON.stringify(entry.detail) : null)
      .run();
  } catch (error) {
    console.error("audit record could not be written:", entry.action, error instanceof Error ? error.message : "");
  }
}

/** The nightly clean-up's statement for records older than a year. */
export const forgetOldAudit = (db: D1Database) =>
  db.prepare("DELETE FROM audit_log WHERE at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)").bind(`-${KEEP_AUDIT_DAYS} days`);

/** More refusals than this in a day is worth a person's attention. */
export const REFUSED_ALERT_AT = 5;

/**
 * Refused attempts in the last 24 hours, by what was attempted: signing in
 * without an invitation, setting up or changing an installation one may not
 * manage, changing or clearing a repository one does not administer.
 */
export async function refusedLastDay(db: D1Database): Promise<Map<string, number>> {
  const { results } = await db
    .prepare("SELECT detail FROM audit_log WHERE action = 'refused' AND at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day') LIMIT 5000")
    .all<{ detail: string | null }>();
  const counts = new Map<string, number>();
  for (const row of results) {
    let attempt = "other";
    try {
      const value = (JSON.parse(row.detail ?? "{}") as { attempt?: unknown }).attempt;
      if (typeof value === "string" && /^[a-z ]{1,40}$/.test(value)) attempt = value;
    } catch {
      // An unreadable record still counts.
    }
    counts.set(attempt, (counts.get(attempt) ?? 0) + 1);
  }
  return counts;
}

/**
 * The line written to the log when refusals pass the threshold, or null.
 * It starts with a fixed word so it can be searched for, or used for a
 * notification, in Cloudflare's logs. Counts and fixed words only.
 */
export function alertLine(counts: Map<string, number>): string | null {
  const total = [...counts.values()].reduce((sum, n) => sum + n, 0);
  if (total < REFUSED_ALERT_AT) return null;
  const parts = [...counts.entries()].sort((a, b) => b[1] - a[1]).map(([attempt, n]) => `${n} x ${attempt}`);
  return `SHIPBRACE-ALERT ${total} refused attempts in the last 24 hours (${parts.join(", ")}). See the audit_log table for who and when.`;
}
