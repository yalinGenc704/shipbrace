import { serve } from "@hono/node-server";
import { createHash } from "node:crypto";
import Anthropic from "@anthropic-ai/sdk";
import {
  createClaudeProposer,
  createOsvSource,
  runSecurityReview,
  type RepoSnapshot,
  type ReviewResult,
} from "@aegis/guardrails";
import { Hono } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { z } from "zod";
import { config } from "./config.ts";
import { handleWebhook } from "./github/webhook.ts";
import { ingest, PathOutsideRootError } from "./ingest.ts";

/**
 * The review API.
 *
 * Deliberately stateless: a review is computed from the code on disk and
 * returned, never stored. That keeps this first version free of a database, and
 * it means there is no stale result that can be mistaken for a current one.
 *
 * The same rules this product applies to generated apps apply here. If they are
 * not good enough for our own server they are not good enough to recommend.
 */
const app = new Hono();

app.use("*", secureHeaders());

app.use(
  "/api/*",
  cors({
    origin: (origin) => (config.allowedOrigins.includes(origin) ? origin : null),
    credentials: true,
    allowMethods: ["GET", "POST"],
  }),
);

// Nothing about the host: once a tunnel is open, anyone can call this.
app.get("/api/health", (c) => c.json({ ok: true }));

const reviewRequest = z.object({
  /** Relative to the configured root. Confined to it by `ingest`. */
  path: z.string().max(400).default("."),
});

/**
 * One handler for both verbs: GET reviews the configured root so the dashboard
 * works with no arguments, POST names a subfolder.
 */
async function review(target: string) {
  const ingested = await ingest(config.reviewRoot, target);
  const result = await reviewOnce(ingested.snapshot);

  return {
    ...result,
    source: {
      path: target,
      filesScanned: ingested.fileCount,
      isGitRepository: ingested.isGitRepository,
      skipped: ingested.skipped,
    },
  };
}

/**
 * The last few results, keyed by exactly what was reviewed. With the AI step
 * on, every review costs money; refreshing the dashboard on unchanged code
 * must not. Any change to any file is a different key, so a stale result is
 * never shown for new code.
 */
const recent = new Map<string, Promise<ReviewResult>>();
const proposer = config.aiReview ? createClaudeProposer(new Anthropic() as never) : undefined;

function reviewOnce(snapshot: RepoSnapshot): Promise<ReviewResult> {
  const hash = createHash("sha256");
  for (const file of [...snapshot.files].sort((a, b) => a.path.localeCompare(b.path))) {
    hash.update(file.path).update("\0").update(file.content).update("\0");
  }
  const key = hash.digest("hex");

  let pending = recent.get(key);
  if (!pending) {
    pending = runSecurityReview(snapshot, {
      ...(config.packageLookup ? { vulnerabilities: createOsvSource() } : {}),
      ...(proposer ? { proposer } : {}),
    });
    // A failed review is not remembered; the next request tries again.
    pending.catch(() => recent.delete(key));
    recent.set(key, pending);
    if (recent.size > 5) recent.delete(recent.keys().next().value!);
  }
  return pending;
}

app.get("/api/review", async (c) => {
  try {
    return c.json(await review("."));
  } catch (error) {
    return failure(c, error);
  }
});

app.post("/api/review", async (c) => {
  const body = reviewRequest.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: "Invalid request." }, 400);

  try {
    return c.json(await review(body.data.path));
  } catch (error) {
    return failure(c, error);
  }
});

/**
 * GitHub's push notifications. The body is read as raw text because the
 * signature covers the exact bytes GitHub sent; parsing first and
 * re-serialising would not match.
 */
app.post("/api/github/webhook", bodyLimit({ maxSize: 5 * 1024 * 1024 }), async (c) => {
  if (!config.github) return c.json({ error: "GitHub integration is not configured." }, 503);

  const result = await handleWebhook(
    {
      secret: config.github.webhookSecret,
      credentials: { appId: config.github.appId, privateKey: config.github.privateKey },
      review: reviewOnce,
      // Answer GitHub now, review afterwards.
      schedule: (task) => void task(),
    },
    { signature: c.req.header("x-hub-signature-256"), event: c.req.header("x-github-event") },
    await c.req.text(),
  );
  return result.status === 204 ? c.body(null, 204) : c.json(result.body, result.status as 200);
});

/**
 * Error responses carry a fixed message, never the underlying detail.
 *
 * A filesystem error names real paths on the host, and the product's own
 * checklist flags exactly this leak under A10. The detail goes to the log,
 * where only the operator sees it.
 */
function failure(c: Parameters<Parameters<Hono["get"]>[1]>[0], error: unknown) {
  if (error instanceof PathOutsideRootError) {
    return c.json({ error: "That folder is outside the area this server may read." }, 403);
  }

  console.error("review failed:", error);
  return c.json({ error: "The review could not be completed." }, 500);
}

serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`review API listening on http://localhost:${info.port}`);
  console.log(`reviewing folders under ${config.reviewRoot}`);
  console.log(config.github ? "GitHub App connected" : "GitHub App not configured");
  console.log(config.aiReview ? "AI suggestions ON (costs API credit per new review)" : "AI suggestions off");
});

export { app };
