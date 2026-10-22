import type { PushJob } from "@shipbrace/server/github/webhook.ts";
import type { Reviewer } from "./reviewer.ts";

/** What the Worker is given by Cloudflare (wrangler.jsonc, plus secrets). */
export interface Env {
  DB: D1Database;
  REVIEWS: Queue<PushJob>;
  REVIEWER: DurableObjectNamespace<Reviewer>;
  ASSETS: Fetcher;

  PUBLIC_URL: string;
  AI_REVIEW: "on" | "off";
  PACKAGE_LOOKUP: "on" | "off";
  GITHUB_APP_ID: string;
  /** Who may sign in while ShipBrace is invite-only; empty = everyone. */
  ALLOWED_GITHUB_USERS?: string;
  /** Most reviews started in any 24 hours, across everyone: a safety cap. */
  DAILY_REVIEW_LIMIT: string;
  /** Most reviews started per calendar month by one GitHub account (installation). */
  MONTHLY_REVIEW_LIMIT?: string;
  /**
   * GitHub user ids (comma-separated) whose reviews may use the AI step --
   * the only part with a per-review cost. Empty means nobody.
   */
  AI_ALLOWED_GITHUB_IDS?: string;
  /** For "Sign in with GitHub", from the App's settings page. Not secret. */
  GITHUB_CLIENT_ID: string;
  /** The App's address on GitHub, for "allow ShipBrace on this repository". */
  GITHUB_APP_SLUG: string;

  /**
   * Cloudflare rate limiting (wrangler.jsonc `ratelimits`): approximate, per
   * Cloudflare location, a brake on floods rather than an exact count.
   * API_LIMITER: requests per signed-in person; ATTEMPT_LIMITER: sign-in
   * attempts (by address, nobody is known yet) and pasted links (by person).
   * Optional so tests and local runs work without them.
   */
  API_LIMITER?: RateLimit;
  ATTEMPT_LIMITER?: RateLimit;

  /** Secrets, set with `wrangler secret put`; never in the config file. */
  GITHUB_PRIVATE_KEY?: string;
  GITHUB_WEBHOOK_SECRET?: string;
  ANTHROPIC_API_KEY?: string;
  /** The App's sign-in secret, from its settings page. */
  GITHUB_CLIENT_SECRET?: string;
  /** 32 random bytes, base64: encrypts the GitHub tokens of signed-in people. */
  SESSION_KEY?: string;
}
