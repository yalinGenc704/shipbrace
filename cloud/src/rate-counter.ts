import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env.ts";
import { allowHit } from "./rate-window.ts";

/**
 * One exact counter per key (a signed-in person, or an address before
 * sign-in). Cloudflare runs a single instance of each, so every server asks
 * the same counter -- unlike the built-in rate limiting binding, which counts
 * on each server separately and barely engaged when measured live.
 *
 * Counts live in memory: an idle counter that Cloudflare puts to sleep starts
 * again from zero, which only matters after a quiet spell, never mid-flood.
 */
export class RateCounter extends DurableObject<Env> {
  private readonly hits = new Map<string, number[]>();

  /** True when this hit is allowed under `limit` per `windowMs`. */
  async hit(bucket: string, limit: number, windowMs: number): Promise<boolean> {
    const times = this.hits.get(bucket) ?? [];
    this.hits.set(bucket, times);
    return allowHit(times, Date.now(), limit, windowMs);
  }
}
