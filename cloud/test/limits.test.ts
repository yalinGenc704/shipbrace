import assert from "node:assert/strict";
import { test } from "node:test";
import { snapshotFromFiles } from "@shipbrace/guardrails";
import { ReviewStoppedError } from "@shipbrace/server/sandbox/stopped.ts";
import type { Env } from "../src/env.ts";
import { claimReviewStart, dailyLimits, forgetOldStarts } from "../src/limits.ts";
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
    INSTALLATION_DAILY_LIMIT: "2",
    ...limits,
  } as unknown as Env;
  return { env, started };
}

const isLimit = (e: unknown) => e instanceof ReviewStoppedError && e.reason === "limit";

test("reviews that time out, crash, or cannot be reached still count toward the limit", async () => {
  const db = fakeD1();
  const replies = [
    async () => Response.json({ type: "stopped", reason: "time" }),
    async () => new Response("not json"),
    async () => Promise.reject(new Error("container gone")),
  ];
  for (const [i, reply] of replies.entries()) {
    const { env } = envWith(db, reply, { INSTALLATION_DAILY_LIMIT: "10" });
    await assert.rejects(reviewInContainer(env, SNAPSHOT, i + 1), (e: unknown) => e instanceof ReviewStoppedError && !isLimit(e));
  }
  const { env, started } = envWith(db, async () => Response.json({ type: "stopped", reason: "crash" }));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 99), isLimit, "three failed starts used up a limit of three");
  assert.equal(started.count, 0, "no container was started over the limit");
});

test("one installation cannot use more than its share of the day", async () => {
  const db = fakeD1();
  const { env, started } = envWith(db, async () => Response.json({ type: "stopped", reason: "crash" }));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 7), (e: unknown) => !isLimit(e));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 7), (e: unknown) => !isLimit(e));
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 7), isLimit, "third start for installation 7 refused");
  assert.equal(started.count, 2);
  await assert.rejects(reviewInContainer(env, SNAPSHOT, 8), (e: unknown) => !isLimit(e), "another installation still gets its turn");
  assert.equal(started.count, 3);
});

test("only starts from the last 24 hours count, and the nightly job removes older ones", async () => {
  const db = fakeD1();
  const limits = { total: 1, perInstallation: 1 };
  await db.prepare("INSERT INTO review_starts (installation_id, started_at) VALUES (7, strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-25 hours'))").run();
  assert.equal(await claimReviewStart(db, 7, limits), true, "yesterday's start does not count");
  assert.equal(await claimReviewStart(db, 7, limits), false);
  await forgetOldStarts(db).run();
  const left = await db.prepare("SELECT count(*) AS n FROM review_starts").first<{ n: number }>();
  assert.equal(left?.n, 1, "only today's start is kept");
});

test("simultaneous starts cannot both take the last place", async () => {
  const db = fakeD1();
  const results = await Promise.all(Array.from({ length: 5 }, (_, i) => claimReviewStart(db, i, { total: 1, perInstallation: 1 })));
  assert.deepEqual(results.filter(Boolean).length, 1);
});

test("an unreadable setting falls back to a low limit, never to none", () => {
  assert.deepEqual(dailyLimits({ DAILY_REVIEW_LIMIT: "500", INSTALLATION_DAILY_LIMIT: "30" }), { total: 500, perInstallation: 30 });
  assert.deepEqual(dailyLimits({}), { total: 20, perInstallation: 10 });
  assert.deepEqual(dailyLimits({ DAILY_REVIEW_LIMIT: "lots", INSTALLATION_DAILY_LIMIT: "-1" }), { total: 20, perInstallation: 10 });
  assert.deepEqual(dailyLimits({ DAILY_REVIEW_LIMIT: "0" }), { total: 0, perInstallation: 10 }, "zero stops all reviews");
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
  const on = envWith(db, done, { PACKAGE_LOOKUP: "on", AI_REVIEW: "on", ANTHROPIC_API_KEY: "k", INSTALLATION_DAILY_LIMIT: "10" } as Partial<Env>);
  await assert.rejects(reviewInContainer(on.env, SNAPSHOT, 1));
  assert.deepEqual(on.started.allowed, ["lookup"], "package lookup is on by default; the AI step is off until switched on");
  const notSetUp = envWith(db, done, { PACKAGE_LOOKUP: "on", INSTALLATION_DAILY_LIMIT: "10" });
  await assert.rejects(reviewInContainer(notSetUp.env, SNAPSHOT, 3));
  assert.deepEqual(notSetUp.started.allowed, [], "an installation nobody has set up sends nothing out");
  const off = envWith(db, done, { PACKAGE_LOOKUP: "off", INSTALLATION_DAILY_LIMIT: "10" });
  await assert.rejects(reviewInContainer(off.env, SNAPSHOT, 2));
  assert.deepEqual(off.started.allowed, [], "switched off for the whole deployment");
});
