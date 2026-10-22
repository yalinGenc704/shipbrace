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
