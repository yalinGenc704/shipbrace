import type { PushJob } from "@aegis/server/github/webhook.ts";
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

  /** Secrets, set with `wrangler secret put`; never in the config file. */
  GITHUB_PRIVATE_KEY?: string;
  GITHUB_WEBHOOK_SECRET?: string;
  ANTHROPIC_API_KEY?: string;
}
