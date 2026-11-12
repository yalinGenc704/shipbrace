/**
 * Repeated webhook deliveries.
 *
 * GitHub gives every message an id and sends the same id again when a
 * message is delivered twice (its own retry, or someone pressing Redeliver).
 * A push that arrives twice used to be reviewed twice and counted twice
 * against the account's reviews. The id is remembered for a week, and only
 * for messages whose signature was already checked and that start a review,
 * so nobody without the secret can fill this table.
 */

const KEEP_DAYS = 7;
/** GitHub's ids are GUIDs; anything else is not remembered or trusted. */
const DELIVERY_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * True the first time this delivery is seen, false for a repeat. A message
 * with no usable id is treated as new: refusing it would drop real pushes,
 * and the review limits still cap what repeats can cost.
 */
export async function firstDelivery(db: D1Database, id: string | undefined): Promise<boolean> {
  if (!id || !DELIVERY_ID.test(id)) return true;
  try {
    const result = await db.prepare("INSERT INTO webhook_deliveries (id) VALUES (?) ON CONFLICT (id) DO NOTHING").bind(id.toLowerCase()).run();
    return (result.meta.changes ?? 0) > 0;
  } catch (error) {
    // The table could not be reached: reviewing a push twice is better than dropping one.
    console.error("delivery ids could not be checked; push let through:", error instanceof Error ? error.message : "");
    return true;
  }
}

/**
 * Forgets one delivery, when the push it carried could not be queued after
 * all: pressing Redeliver on GitHub must then start the review, not be
 * answered "already received".
 */
export async function forgetDelivery(db: D1Database, id: string | undefined): Promise<void> {
  if (!id || !DELIVERY_ID.test(id)) return;
  await db.prepare("DELETE FROM webhook_deliveries WHERE id = ?").bind(id.toLowerCase()).run().catch(() => {});
}

/**
 * Queues a push's jobs unless this delivery was already received. Returns
 * false for a repeat. If queueing fails, the delivery is forgotten again
 * before the error is passed on.
 */
export async function queueOnce(db: D1Database, id: string | undefined, send: () => Promise<void>): Promise<boolean> {
  if (!(await firstDelivery(db, id))) return false;
  try {
    await send();
  } catch (error) {
    await forgetDelivery(db, id);
    throw error;
  }
  return true;
}

/** The nightly clean-up's statement for ids older than a week. */
export const forgetOldDeliveries = (db: D1Database) =>
  db.prepare("DELETE FROM webhook_deliveries WHERE received_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)").bind(`-${KEEP_DAYS} days`);
