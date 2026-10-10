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
  /** For "Sign in with GitHub", from the App's settings page. Not secret. */
  GITHUB_CLIENT_ID: string;
  /** The App's address on GitHub, for "allow ShipBrace on this repository". */
  GITHUB_APP_SLUG: string;

  /** Secrets, set with `wrangler secret put`; never in the config file. */
  GITHUB_PRIVATE_KEY?: string;
  GITHUB_WEBHOOK_SECRET?: string;
  ANTHROPIC_API_KEY?: string;
  /** The App's sign-in secret, from its settings page. */
  GITHUB_CLIENT_SECRET?: string;
  /** 32 random bytes, base64: encrypts the GitHub tokens of signed-in people. */
  SESSION_KEY?: string;
}
