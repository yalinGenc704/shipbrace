/**
 * An exact sliding window: at most `limit` allowed hits in any `windowMs`.
 * Only allowed hits are remembered, so someone who keeps trying while
 * refused does not push their own wait further out.
 */
export function allowHit(times: number[], now: number, limit: number, windowMs: number): boolean {
  while (times.length > 0 && times[0]! <= now - windowMs) times.shift();
  if (times.length >= limit) return false;
  times.push(now);
  return true;
}
