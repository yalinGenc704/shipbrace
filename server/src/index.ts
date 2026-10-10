import { serve } from "@hono/node-server";
import { serveStatic } from "@hono/node-server/serve-static";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import Anthropic from "@anthropic-ai/sdk";
import { createClaudeProposer, createOsvSource, type RepoSnapshot, type ReviewResult } from "@aegis/guardrails";
import { Hono, type Context } from "hono";
import { bodyLimit } from "hono/body-limit";
import { cors } from "hono/cors";
import { secureHeaders } from "hono/secure-headers";
import { z } from "zod";
import { config } from "./config.ts";
import { handleWebhook } from "./github/webhook.ts";
import { connect, migrate, postgresHistory, type ReviewHistory } from "./history.ts";
import { historyRoutes } from "./history-routes.ts";
import { ingest, PathOutsideRootError } from "./ingest.ts";
import { createRemoteReviewer } from "./sandbox/remote.ts";
import { createSandbox, ReviewStoppedError } from "./sandbox/sandbox.ts";

/**
 * The review API.
 *
 * A review of a local folder is computed from the code on disk and returned,
 * never stored, so there is no stale result to mistake for a current one.
 * Reviews of GitHub pushes are also kept, when a database is configured, each
 * labelled with the commit it describes (see history.ts).
 *
 * The same rules this product applies to generated apps apply here. If they are
 * not good enough for our own server they are not good enough to recommend.
 */
const history: ReviewHistory | null = config.databaseUrl ? postgresHistory(connect(config.databaseUrl)) : null;
if (config.databaseUrl) {
  const sql = connect(config.databaseUrl);
  try {
    await migrate(sql);
  } catch (error) {
    // The message only: a connection error can quote the address, password included.
    console.error("Could not prepare the review history database:", error instanceof Error ? error.message.replace(/postgres(ql)?:\/\/\S+/g, "<DATABASE_URL>") : "unknown error");
    process.exit(1);
  } finally {
    await sql.end({ timeout: 5 });
  }
}

const app = new Hono();

/**
 * Everything the dashboard loads comes from this server, so the browser is
 * told to refuse scripts, styles and connections from anywhere else. If
 * something hostile ever reached a page, it could neither load more code nor
 * send what it read elsewhere.
 */
app.use(
  "*",
  secureHeaders({
    contentSecurityPolicy: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'none'"],
      formAction: ["'none'"],
      frameAncestors: ["'none'"],
    },
  }),
);

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

app.route("/api", historyRoutes(history));

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
/**
 * Every review reads code sealed off: in the review container when hosted
 * (sandbox/reviewer.ts), otherwise in a sealed process here (sandbox/sandbox.ts).
 */
const sealedReview = config.reviewerSocket ? createRemoteReviewer(config.reviewerSocket) : createSandbox();

function reviewOnce(snapshot: RepoSnapshot): Promise<ReviewResult> {
  const hash = createHash("sha256");
  for (const file of [...snapshot.files].sort((a, b) => a.path.localeCompare(b.path))) {
    hash.update(file.path).update("\0").update(file.content).update("\0");
  }
  const key = hash.digest("hex");

  let pending = recent.get(key);
  if (!pending) {
    pending = sealedReview(snapshot, {
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

// Off on a hosted server: no route, so nothing to call.
if (config.localReview) {
  app.get("/api/review", async (c) => {
    try {
      return c.json(await review("."));
    } catch (error) {
      return failure(c, error);
    }
  });

  app.post("/api/review", bodyLimit({ maxSize: 16 * 1024 }), async (c) => {
    const body = reviewRequest.safeParse(await c.req.json().catch(() => ({})));
    if (!body.success) return c.json({ error: "Invalid request." }, 400);

    try {
      return c.json(await review(body.data.path));
    } catch (error) {
      return failure(c, error);
    }
  });
}

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
      ...(history ? { history } : {}),
      ...(config.publicUrl ? { publicUrl: config.publicUrl } : {}),
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
function failure(c: Context, error: unknown) {
  if (error instanceof PathOutsideRootError) {
    return c.json({ error: "That folder is outside the area this server may read." }, 403);
  }
  if (error instanceof ReviewStoppedError) {
    console.error("review stopped:", error.reason);
    return c.json({ error: error.userMessage }, 500);
  }

  console.error("review failed:", error);
  return c.json({ error: "The review could not be completed." }, 500);
}

/**
 * The built dashboard (`npm run build --workspace @aegis/app`), so the links in
 * GitHub checks open on the same address as the API. Each page the dashboard
 * has gets its one HTML file, which then picks what to show; anything else is
 * a 404 rather than a page.
 */
const dashboard = fileURLToPath(new URL("../../app/dist", import.meta.url));
if (existsSync(dashboard)) {
  app.use("/assets/*", serveStatic({ root: dashboard }));
  for (const page of [...(config.localReview ? ["/"] : []), "/reviews/:id", "/history/:id"]) {
    app.get(page, serveStatic({ root: dashboard, path: "index.html" }));
  }
}

serve({ fetch: app.fetch, port: config.port }, (info) => {
  console.log(`review API listening on http://localhost:${info.port}`);
  console.log(config.localReview ? `reviewing folders under ${config.reviewRoot}` : "Folder reviews off (LOCAL_REVIEW=off)");
  console.log(config.github ? "GitHub App connected" : "GitHub App not configured");
  console.log(config.reviewerSocket ? `Reviews run in the review container (${config.reviewerSocket})` : "Reviews run in a sealed process on this machine");
  console.log(history ? "Review history ON (PostgreSQL)" : "Review history off (no DATABASE_URL)");
  console.log(existsSync(dashboard) ? "Dashboard served from app/dist" : "Dashboard not built; run it with Vite instead");
  console.log(config.aiReview ? "AI suggestions ON (costs API credit per new review)" : "AI suggestions off");
});

export { app };
