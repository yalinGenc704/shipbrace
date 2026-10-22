import assert from "node:assert/strict";
import { test } from "node:test";
import { snapshotFromFiles } from "@shipbrace/guardrails";
import { ReviewStoppedError } from "@shipbrace/server/sandbox/stopped.ts";
import type { Env } from "../src/env.ts";
import { claimReviewStart, forgetOldStarts, nextReset, reviewLimits, usedThisMonth } from "../src/limits.ts";
import { reviewInContainer } from "../src/review-container.ts";
import { fakeD1 } from "./fake-d1.ts";

/**
 * The daily limits are the only cap on what reviews cost, so every review
 * that starts must count, however it ends.
 */

const SNAPSHOT = snapshotFromFiles([{ path: "index.js", content: "console.log(1);\n" }]);

/** A Worker environment whose reviewer container ends every review with `reply`. */
function envWith(db: D1Database, reply: () => Promise<Response>, limits: Partial<Env> = {}) {
  const started = { count: 0, allowed: undefined as string[] | undefined };
  const env = {
    DB: db,
    REVIEWER: {
      newUniqueId: () => "id",
      get: () => ({
        fetch: () => {
          started.count++;
          return reply();
        },
        allow: async (steps: string[]) => {
          started.allowed = steps;
        },
        destroy: async () => {},
      }),
    },
    AI_REVIEW: "off",
    PACKAGE_LOOKUP: "off",
    DAILY_REVIEW_LIMIT: "3",
    MONTHLY_REVIEW_LIMIT: "2",
    ...limits,
  } as unknown as Env;
  return { env, started };
}

const isLimit = (e: unknown) => e instanceof ReviewStoppedError && e.reason === "limit";
const isMonthly = (e: unknown) => e instanceof ReviewStoppedError && e.reason === "monthly-limit";

test("reviews that time out, crash, or cannot be reached still count toward the limit", async () => {
  const db = fakeD1();
  const replies = [
    async () => Response.json({ type: "stopped", reason: "time" }),
    async () => new Response("not json"),
    async () => Promise.reject(new Error("container gone")),
  ];
  for (const [i, reply] of replies.entries()) {
    const { env } = envWith(db, reply, { MONTHLY_REVIEW_LIMIT: "10" });
    await assert.rejects(reviewInContainer(env, SNAPSHOT, i + 1), (e: unknown) => e instanceof ReviewStoppedError && !isLimit(e));
  }
  const { env, started } = envWith(db, async () => Response.json({ type: "stopped", reason: "crash" }));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 99), isLimit, "three failed starts used up a limit of three");
  assert.equal(started.count, 0, "no container was started over the limit");
});

test("one GitHub account cannot use more than its reviews for the month", async () => {
  const db = fakeD1();
  const { env, started } = envWith(db, async () => Response.json({ type: "stopped", reason: "crash" }));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 7), (e: unknown) => !isLimit(e) && !isMonthly(e));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 7), (e: unknown) => !isLimit(e) && !isMonthly(e));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 7), isMonthly, "third start this month for account 7 refused, and says why");
  assert.equal(started.count, 2);
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 8), (e: unknown) => !isMonthly(e), "another account still gets its turn");
  assert.equal(started.count, 3);
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 9), isLimit, "then the daily safety cap of three stops everyone");
});

test("the month resets on the 1st; the daily cap looks back 24 hours", async () => {
  const db = fakeD1();
  const limits = { monthly: 1, daily: 5 };
  await db.prepare("INSERT INTO review_starts (installation_id, started_at) VALUES (7, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', 'start of month', '-1 second'))").run();
  assert.deepEqual(await claimReviewStart(db, 7, limits), { ok: true }, "last month's start does not count");
  assert.deepEqual(await claimReviewStart(db, 7, limits), { ok: false, reason: "monthly-limit" });
  assert.equal(await usedThisMonth(db, 7), 1);
  await db.prepare("INSERT INTO review_starts (installation_id, started_at) VALUES (8, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-25 hours'))").run();
  assert.deepEqual(await claimReviewStart(db, 9, { monthly: 10, daily: 1 }), { ok: false, reason: "limit" }, "one start in the last 24 hours fills a cap of one");
});

test("the nightly job keeps this month and last month, and removes older starts", async () => {
  const db = fakeD1();
  await db.prepare("INSERT INTO review_starts (installation_id, started_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', 'start of month', '-1 month', '-1 second'))").run();
  await db.prepare("INSERT INTO review_starts (installation_id, started_at) VALUES (1, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', 'start of month', '-1 month'))").run();
  await db.prepare("INSERT INTO review_starts (installation_id) VALUES (1)").run();
  await forgetOldStarts(db).run();
  const left = await db.prepare("SELECT count(*) AS n FROM review_starts").first<{ n: number }>();
  assert.equal(left?.n, 2);
});

test("simultaneous starts cannot both take the last place", async () => {
  const db = fakeD1();
  const results = await Promise.all(Array.from({ length: 5 }, (_, i) => claimReviewStart(db, i, { monthly: 1, daily: 1 })));
  assert.equal(results.filter((r) => r.ok).length, 1);
});

test("an unreadable setting falls back to a low limit, never to none", () => {
  assert.deepEqual(reviewLimits({ DAILY_REVIEW_LIMIT: "500", MONTHLY_REVIEW_LIMIT: "300" }), { daily: 500, monthly: 300 });
  assert.deepEqual(reviewLimits({}), { daily: 50, monthly: 50 });
  assert.deepEqual(reviewLimits({ DAILY_REVIEW_LIMIT: "lots", MONTHLY_REVIEW_LIMIT: "-1" }), { daily: 50, monthly: 50 });
  assert.deepEqual(reviewLimits({ DAILY_REVIEW_LIMIT: "0" }), { daily: 0, monthly: 50 }, "zero stops all reviews");
});

test("the reset date is the 1st of next month, also across a year end", () => {
  assert.equal(nextReset(new Date("2026-10-21T12:00:00Z")), "2026-11-01T00:00:00.000Z");
  assert.equal(nextReset(new Date("2026-12-31T23:59:00Z")), "2027-01-01T00:00:00.000Z");
});

test("a finished review comes back unchanged", async () => {
  const result = { modules: [], summary: {}, stats: {} };
  const { env } = envWith(fakeD1(), async () => Response.json({ type: "done", result }));
  assert.deepEqual(await reviewInContainer(env, SNAPSHOT, 1), result);
});

test("a review is allowed only the outside steps its installation has switched on", async () => {
  const db = fakeD1();
  const done = async () => Response.json({ type: "stopped", reason: "crash" });
  // A set-up installation: package lookup on (the default), AI off.
  await db.prepare("INSERT INTO users (github_id, login) VALUES (5, 'ada')").run();
  await db.prepare("INSERT INTO installations (installation_id, set_up_by) VALUES (1, 5)").run();
  const on = envWith(db, done, { PACKAGE_LOOKUP: "on", AI_REVIEW: "on", ANTHROPIC_API_KEY: "k", MONTHLY_REVIEW_LIMIT: "10" } as Partial<Env>);
  await assert.rejects(reviewInContainer(on.env, SNAPSHOT, 1));
  assert.deepEqual(on.started.allowed, ["lookup"], "package lookup is on by default; the AI step is off until switched on");
  const notSetUp = envWith(db, done, { PACKAGE_LOOKUP: "on", MONTHLY_REVIEW_LIMIT: "10" });
  await assert.rejects(reviewInContainer(notSetUp.env, SNAPSHOT, 3));
  assert.deepEqual(notSetUp.started.allowed, [], "an installation nobody has set up sends nothing out");
  const off = envWith(db, done, { PACKAGE_LOOKUP: "off", MONTHLY_REVIEW_LIMIT: "10" });
  await assert.rejects(reviewInContainer(off.env, SNAPSHOT, 2));
  assert.deepEqual(off.started.allowed, [], "switched off for the whole deployment");
});

test("the AI step runs only for reviews started by someone on the AI list", async () => {
  const db = fakeD1();
  await db.prepare("INSERT INTO users (github_id, login) VALUES (5, 'ada')").run();
  await db.prepare("INSERT INTO installations (installation_id, set_up_by, ai_review) VALUES (1, 5, 1)").run();
  const done = async () => Response.json({ type: "stopped", reason: "crash" });
  const settings = { AI_REVIEW: "on", ANTHROPIC_API_KEY: "k", AI_ALLOWED_GITHUB_IDS: "42", PACKAGE_LOOKUP: "off", MONTHLY_REVIEW_LIMIT: "10" } as Partial<Env>;
  const listed = envWith(db, done, settings);
  await assert.rejects(reviewInContainer(listed.env, SNAPSHOT, 1, 42));
  assert.deepEqual(listed.started.allowed, ["propose"]);
  const other = envWith(db, done, settings);
  await assert.rejects(reviewInContainer(other.env, SNAPSHOT, 1, 43));
  assert.deepEqual(other.started.allowed, [], "someone not on the list gets no AI, even with the switch on");
  const unknown = envWith(db, done, settings);
  await assert.rejects(reviewInContainer(unknown.env, SNAPSHOT, 1));
  assert.deepEqual(unknown.started.allowed, [], "a review with no known starter gets no AI");
});
