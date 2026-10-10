import type { RepoSnapshot, ReviewResult } from "@aegis/guardrails";
import { OSV_NOTICE } from "@aegis/guardrails/vulnerabilities";
import { handleWebhook, reviewPush, type PushJob, type ReviewDeps } from "@aegis/server/github/webhook.ts";
import type { ReviewReply, ReviewRequest } from "@aegis/server/sandbox/reviewer-http.ts";
import { ReviewStoppedError } from "@aegis/server/sandbox/stopped.ts";
import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { accountRoutes, forgetInstallation, installationIsSetUp } from "./accounts.ts";
import type { Env } from "./env.ts";
import { d1History } from "./history-d1.ts";

export { ContainerProxy } from "@cloudflare/containers";
export { Reviewer } from "./reviewer.ts";

/**
 * ShipBrace (still named Aegis in the code) on Cloudflare.
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

const STOP_REASONS = new Set(["time", "memory", "crash", "busy", "unavailable"]);
const MAX_WEBHOOK_BYTES = 5 * 1024 * 1024;

const app = new Hono<{ Bindings: Env }>();

app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
  }),
);

// Nothing about the deployment: anyone can call this.
app.get("/api/health", (c) => c.json({ ok: true }));

app.post("/api/github/webhook", async (c) => {
  const secret = c.env.GITHUB_WEBHOOK_SECRET;
  if (!secret || !c.env.GITHUB_PRIVATE_KEY) return c.json({ error: "GitHub integration is not configured." }, 503);
  if (Number(c.req.header("content-length") ?? 0) > MAX_WEBHOOK_BYTES) return c.json({ error: "Too large." }, 413);

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

/**
 * One review in its own container, which is destroyed afterwards.
 *
 * Above DAILY_REVIEW_LIMIT reviews in a day, across everyone, no more are
 * started: a ceiling on what any burst -- or abuse -- can cost. The check
 * says so in plain words instead.
 */
async function reviewInContainer(env: Env, snapshot: RepoSnapshot): Promise<ReviewResult> {
  const today = await env.DB.prepare("SELECT count(*) AS n FROM reviews WHERE created_at > strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')").first<{ n: number }>();
  if ((today?.n ?? 0) >= Number(env.DAILY_REVIEW_LIMIT || 200)) {
    console.error("daily review limit reached; review not started");
    throw new ReviewStoppedError("busy");
  }
  const reviewer = env.REVIEWER.get(env.REVIEWER.newUniqueId());
  const request: ReviewRequest = {
    files: snapshot.files.map(({ path, content }) => ({ path, content })),
    tracked: [...snapshot.tracked],
    ...(env.AI_REVIEW === "on" && env.ANTHROPIC_API_KEY ? { proposer: { name: "claude" } } : {}),
    ...(env.PACKAGE_LOOKUP === "on" ? { vulnerabilities: { notice: OSV_NOTICE } } : {}),
  };

  try {
    let response: Response;
    try {
      response = await reviewer.fetch("http://reviewer/review", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(request),
      });
    } catch (error) {
      console.error("reviewer container could not be reached:", error);
      throw new ReviewStoppedError("unavailable");
    }
    // The container reads hostile code; what it says is checked, not trusted.
    const reply = (await response.json().catch(() => null)) as ReviewReply | null;
    if (reply?.type === "done" && isReviewResult(reply.result)) return reply.result;
    if (reply?.type === "stopped" && STOP_REASONS.has(reply.reason)) throw new ReviewStoppedError(reply.reason as never);
    throw new ReviewStoppedError("crash");
  } finally {
    await reviewer.destroy().catch(() => {});
  }
}

function isReviewResult(value: unknown): value is ReviewResult {
  const r = value as ReviewResult;
  return typeof r === "object" && r !== null && Array.isArray(r.modules) && typeof r.summary === "object" && typeof r.stats === "object";
}

function reviewDeps(env: Env): ReviewDeps {
  return {
    credentials: { appId: env.GITHUB_APP_ID, privateKey: env.GITHUB_PRIVATE_KEY ?? "" },
    review: (snapshot) => reviewInContainer(env, snapshot),
    history: d1History(env.DB),
    publicUrl: env.PUBLIC_URL.replace(/\/+$/, ""),
    log: (message, error) => console.error(message, error instanceof Error ? error.message : ""),
  };
}

/** How long kept reviews are kept. Older ones are deleted every night. */
const KEEP_DAYS = 90;

export default {
  fetch: app.fetch,

  /** Nightly: old reviews, finished sign-ins, and spent rate-limit records go. */
  async scheduled(_event: ScheduledController, env: Env): Promise<void> {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM reviews WHERE created_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', ?)").bind(`-${KEEP_DAYS} days`),
      env.DB.prepare("DELETE FROM sessions WHERE expires_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now')"),
      env.DB.prepare("DELETE FROM review_requests WHERE requested_at < strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')"),
    ]);
  },

  /**
   * One push at a time per message. Never retried: a failed review already
   * posts "could not be completed" on the check, and a retry would post a
   * second check for the same commit.
   */
  async queue(batch: MessageBatch<PushJob>, env: Env): Promise<void> {
    for (const message of batch.messages) {
      await reviewPush(reviewDeps(env), message.body);
      message.ack();
    }
  },
} satisfies ExportedHandler<Env, PushJob>;
