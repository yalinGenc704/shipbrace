import assert from "node:assert/strict";
import { after, before, test } from "node:test";
import { runSecurityReview, snapshotFromFiles } from "@aegis/guardrails";
import { connect, migrate, newLinkId, postgresHistory, type NewReview } from "../src/history.ts";
import { historyRoutes } from "../src/history-routes.ts";

/**
 * Runs against a real PostgreSQL, because the queries are what is being tested.
 * Set TEST_DATABASE_URL to a database whose name ends in `_test`; its tables
 * are dropped at the start. Without it these tests are skipped, and say so.
 */
const url = process.env.TEST_DATABASE_URL;
const skip = !url
  ? "set TEST_DATABASE_URL (e.g. postgres:///aegis_test) to run the review history tests"
  : !/_test(\?|$)/.test(url)
  ? "TEST_DATABASE_URL must name a database ending in _test; its tables are dropped"
  : false;

const sql = skip ? null : connect(url!);
const history = sql ? postgresHistory(sql) : null;

before(async () => {
  if (!sql) return;
  await sql`DROP TABLE IF EXISTS reviews, repositories, schema_migrations`;
  await migrate(sql);
});

after(async () => {
  await history?.close();
});

const VULNERABLE = [
  'import { Hono } from "hono";',
  "const app = new Hono();",
  'app.get("/api/reports/:id", async (c) => {',
  '  const id = c.req.param("id");',
  "  return c.json(await db.query(`SELECT * FROM reports WHERE id = ${id}`));",
  "});",
].join("\n");

async function newReview(over: Partial<NewReview> = {}): Promise<NewReview> {
  const result = await runSecurityReview(snapshotFromFiles([{ path: "server/src/api.ts", content: VULNERABLE }]));
  return {
    githubId: 1,
    owner: "murat",
    repo: "shop",
    commitSha: "a".repeat(40),
    conclusion: "failure",
    title: "1 high-risk problem to fix",
    result,
    skipped: { notReadable: 0, tooLarge: 0, overLimit: 0, treeTruncated: false },
    ...over,
  };
}

test("running the setup twice changes nothing", { skip }, async () => {
  await migrate(sql!);
  const [row] = await sql!<{ count: number }[]>`SELECT count(*)::int AS count FROM schema_migrations`;
  assert.equal(row!.count, 1);
});

test("a saved review comes back exactly as it was reviewed", { skip }, async () => {
  const review = await newReview({ githubId: 10 });
  const { reviewId, historyId } = await history!.record(review);

  const stored = await history!.review(reviewId);
  assert.ok(stored);
  assert.deepEqual(stored.result, JSON.parse(JSON.stringify(review.result)), "the full review, not a summary of it");
  assert.equal(stored.commitSha, review.commitSha);
  assert.equal(stored.conclusion, "failure");
  assert.deepEqual(stored.repository, { owner: "murat", name: "shop", historyId });
  assert.equal(stored.counts.high, review.result.summary.high);
  assert.ok(!Number.isNaN(Date.parse(stored.createdAt)));
});

test("a repository's history lists its reviews, newest first, and only its own", { skip }, async () => {
  const first = await history!.record(await newReview({ githubId: 20, commitSha: "1".repeat(40) }));
  const second = await history!.record(await newReview({ githubId: 20, commitSha: "2".repeat(40), conclusion: "success" }));
  await history!.record(await newReview({ githubId: 21, repo: "other" }));

  assert.equal(first.historyId, second.historyId, "one history per repository");
  const list = await history!.repository(first.historyId);
  assert.deepEqual(list?.reviews.map((r) => r.id), [second.reviewId, first.reviewId]);
  assert.deepEqual(list?.reviews.map((r) => r.conclusion), ["success", "failure"]);
});

test("a renamed repository keeps its history and its link, under the new name", { skip }, async () => {
  const before = await history!.record(await newReview({ githubId: 30, repo: "old-name" }));
  const after = await history!.record(await newReview({ githubId: 30, owner: "new-owner", repo: "new-name" }));

  assert.equal(after.historyId, before.historyId);
  const list = await history!.repository(after.historyId);
  assert.equal(list?.owner, "new-owner");
  assert.equal(list?.name, "new-name");
  assert.equal(list?.reviews.length, 2);
});

test("unknown and malformed addresses find nothing", { skip }, async () => {
  assert.equal(await history!.review(newLinkId()), null);
  assert.equal(await history!.repository(newLinkId()), null);
  assert.equal(await history!.review("' OR 1=1 --"), null);
  assert.equal(await history!.review(""), null);
});

test("addresses are random and long enough not to be guessed", () => {
  const ids = new Set(Array.from({ length: 1000 }, newLinkId));
  assert.equal(ids.size, 1000);
  for (const id of ids) assert.match(id, /^[A-Za-z0-9_-]{24}$/);
});

// --- the web addresses ----------------------------------------------------------------

test("the pages say plainly when there is no history, and leave no copies behind", { skip }, async () => {
  const { reviewId, historyId } = await history!.record(await newReview({ githubId: 40 }));
  const routes = historyRoutes(history!);

  const found = await routes.request(`/reviews/${reviewId}`);
  assert.equal(found.status, 200);
  assert.equal(found.headers.get("cache-control"), "no-store");
  assert.equal(found.headers.get("x-robots-tag"), "noindex");
  assert.equal(((await found.json()) as any).repository.historyId, historyId);

  assert.equal((await routes.request(`/history/${historyId}`)).status, 200);
  assert.equal((await routes.request(`/reviews/${newLinkId()}`)).status, 404);
  assert.equal((await routes.request("/history/short")).status, 404);
});

test("without a database the pages say so instead of pretending nothing was found", async () => {
  const routes = historyRoutes(null);
  const response = await routes.request(`/reviews/${newLinkId()}`);
  assert.equal(response.status, 503);
  assert.match(((await response.json()) as any).error, /not configured/);
});

test("a database failure is a fixed message; the detail stays in the log", async () => {
  const logged: unknown[] = [];
  const broken = {
    record: () => Promise.reject(new Error("unused")),
    review: () => Promise.reject(new Error("connect ECONNREFUSED 10.0.0.5:5432")),
    repository: () => Promise.reject(new Error("unused")),
    close: async () => {},
  };
  const response = await historyRoutes(broken, (_m, e) => void logged.push(e)).request(`/reviews/${newLinkId()}`);
  assert.equal(response.status, 500);
  assert.ok(!(await response.text()).includes("10.0.0.5"));
  assert.equal(logged.length, 1);
});
