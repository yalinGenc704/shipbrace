import { handleWebhook, reviewPush, type PushJob, type ReviewDeps } from "@shipbrace/server/github/webhook.ts";
import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { accountRoutes, forgetInstallation, installationIsSetUp } from "./accounts.ts";
import { forgetOldAudit } from "./audit.ts";
import type { Env } from "./env.ts";
import { d1History } from "./history-d1.ts";
import { forgetOldStarts } from "./limits.ts";
import { reviewInContainer } from "./review-container.ts";
import { webhookBodyLimit } from "./webhook-limit.ts";

export { ContainerProxy } from "@cloudflare/containers";
export { Reviewer } from "./reviewer.ts";

/**
 * ShipBrace (still named ShipBrace in the code) on Cloudflare.
 *
 *   GitHub push ──▶ this Worker: check the signature, queue the push, answer
 *                    │
 *                    ▼
 *                  queue ──▶ fetch the code from GitHub, start a reviewer
 *                             container (no internet), post the check, keep
 *                             the result in D1
 *
 * The dashboard's files are served by Cloudflare directly (wrangler.jsonc,
 * `assets`); only /api/* reaches this code.
 */

const app = new Hono<{ Bindings: Env }>();

app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
  }),
);

// Nothing about the deployment: anyone can call this.
app.get("/api/health", (c) => c.json({ ok: true }));

app.post("/api/github/webhook", webhookBodyLimit, async (c) => {
  const secret = c.env.GITHUB_WEBHOOK_SECRET;
  if (!secret || !c.env.GITHUB_PRIVATE_KEY) return c.json({ error: "GitHub integration is not configured." }, 503);

  const jobs: PushJob[] = [];
  const result = await handleWebhook(
    {
      secret,
      schedule: (job) => void jobs.push(job),
      isSetUp: (id) => installationIsSetUp(c.env.DB, id),
      forget: (id, repos) => forgetInstallation(c.env.DB, id, repos),
    },
    { signature: c.req.header("x-hub-signature-256"), event: c.req.header("x-github-event") },
    await c.req.text(),
  );
  // Queued before answering, so an accepted push is never lost.
  for (const job of jobs) await c.env.REVIEWS.send(job);
  return result.status === 204 ? c.body(null, 204) : c.json(result.body, result.status as 200);
});

// There is no folder to review on Cloudflare (that is the laptop's feature).
// Answered before sign-in, so the front page can tell and show the home page.
app.get("/api/review", (c) => c.json({ error: "Not found." }, 404));

// Sign-in, the notices, pasting a link, and kept reviews for people who may see them.
app.route("/", accountRoutes());

app.all("/api/*", (c) => c.json({ error: "Not found." }, 404));

function reviewDeps(env: Env, job: PushJob): ReviewDeps {
  return {
    credentials: { appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_PRIVATE_KEY ?? "" },
    review: (snapshot) => reviewInContainer(env, snapshot, job.installationId),
    history: d1History(env.DB),
    publicUrl: env.PUBLIC_URL.replace(/\/+$/, ""),
    log: (message, error) => console.error(message, error instanceof Error ? error.message : ""),
  };
}

/** How long kept reviews are kept. Older ones are deleted every night. */
const KEEP_DAYS = 90;

export default {
  fetch: app.fetch,

  /** Nightly: old reviews, finished sign-ins, spent rate-limit records, and year-old audit records go. */
  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM reviews WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)").bind(`-${KEEP_DAYS} days`),
      env.DB.prepare("DELETE FROM sessions WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"),
      env.DB.prepare("DELETE FROM review_requests WHERE requested_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')"),
      forgetOldStarts(env.DB),
      forgetOldAudit(env.DB),
    ]);
  },

  /**
   * One push at a time per message. Never retried: a failed review already
   * posts "could not be completed" on the check, and a retry would post a
   * second check for the same commit.
   */
  async queue(batch: MessageBatch<PushJob>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      await reviewPush(reviewDeps(env, message.body), message.body);
      message.ack();
    }
  },
} satisfies ExportedHandler<Env, PushJob>;
