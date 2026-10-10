import type { RepoSnapshot, ReviewResult } from "@aegis/guardrails";
import { OSV_NOTICE } from "@aegis/guardrails/vulnerabilities";
import { handleWebhook, reviewPush, type PushJob, type ReviewDeps } from "@aegis/server/github/webhook.ts";
import { historyRoutes } from "@aegis/server/history-routes.ts";
import type { ReviewReply, ReviewRequest } from "@aegis/server/sandbox/reviewer-http.ts";
import { ReviewStoppedError } from "@aegis/server/sandbox/stopped.ts";
import { Hono } from "hono";
import { secureHeaders } from "hono/secure-headers";
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

app.all("/api/reviews/*", (c) => kept(c.req.raw, c.env));
app.all("/api/history/*", (c) => kept(c.req.raw, c.env));

/** Kept reviews, read back by unguessable link (server/src/history-routes.ts). */
function kept(request: Request, env: Env) {
  const url = new URL(request.url);
  url.pathname = url.pathname.replace(/^\/api/, "");
  return historyRoutes(d1History(env.DB)).fetch(new Request(url, request));
}

app.post("/api/github/webhook", async (c) => {
  const secret = c.env.GITHUB_WEBHOOK_SECRET;
  if (!secret || !c.env.GITHUB_PRIVATE_KEY) return c.json({ error: "GitHub integration is not configured." }, 503);
  if (Number(c.req.header("content-length") ?? 0) > MAX_WEBHOOK_BYTES) return c.json({ error: "Too large." }, 413);

  const jobs: PushJob[] = [];
  const result = await handleWebhook(
    { secret, schedule: (job) => void jobs.push(job) },
    { signature: c.req.header("x-hub-signature-256"), event: c.req.header("x-github-event") },
    await c.req.text(),
  );
  // Queued before answering, so an accepted push is never lost.
  for (const job of jobs) await c.env.REVIEWS.send(job);
  return result.status === 204 ? c.body(null, 204) : c.json(result.body, result.status as 200);
});

app.all("/api/*", (c) => c.json({ error: "Not found." }, 404));

/** One review in its own container, which is destroyed afterwards. */
async function reviewInContainer(env: Env, snapshot: RepoSnapshot): Promise<ReviewResult> {
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

export default {
  fetch: app.fetch,

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
