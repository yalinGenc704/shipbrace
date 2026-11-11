import assert from "node:assert/strict";
import { test } from "node:test";
import { runSecurityReview } from "@shipbrace/guardrails";
import { handleReview, type ReviewRequest } from "../src/sandbox/reviewer-http.ts";

/**
 * The reviewer as it runs inside Cloudflare's container, with the Worker's
 * answers at `shipbrace.internal` played by a stand-in. The review itself
 * runs unsealed here: the wall is tested in sandbox.test.ts, the asking here.
 */

const FILES = [
  {
    path: "server/src/index.ts",
    content: [
      'import { Hono } from "hono";',
      "const app = new Hono();",
      "const toSafeId = (v) => parseInt(v, 10);",
      'app.get("/orders", async (c) => {',
      '  const id = toSafeId(c.req.query("id"));',
      "  return c.json(await db.query(`SELECT * FROM orders WHERE id = ${id}`));",
      "});",
    ].join("\n"),
  },
];
const request = (over: Partial<ReviewRequest> = {}): ReviewRequest => ({ files: FILES, tracked: FILES.map((f) => f.path), ...over });

/** Replaces `fetch` for one test and records what was asked of the Worker. */
async function withWorker<T>(answer: (step: string, input: unknown) => Response, run: (asked: Array<{ step: string; input: unknown }>) => Promise<T>): Promise<T> {
  const asked: Array<{ step: string; input: unknown }> = [];
  const real = globalThis.fetch;
  globalThis.fetch = (async (url: string, init?: { body?: string }) => {
    const step = String(url).replace("http://shipbrace.internal/ask/", "");
    const input = JSON.parse(init?.body ?? "null") as unknown;
    asked.push({ step, input });
    return answer(step, input);
  }) as typeof fetch;
  try {
    return await run(asked);
  } finally {
    globalThis.fetch = real;
  }
}

const tracedRisks = (reply: Awaited<ReturnType<typeof handleReview>>) =>
  reply.type === "done" ? reply.result.modules.flatMap((m) => m.items.flatMap((i) => i.risks)).filter((r) => r.id.startsWith("taint/")) : [];

test("the reviewer asks the Worker to judge cleaning functions only when told it may", async () => {
  await withWorker(
    () => Response.json({ error: "failed" }, { status: 403 }),
    async (asked) => {
      const reply = await handleReview(request(), runSecurityReview);
      assert.equal(reply.type, "done");
      assert.equal(asked.length, 0, "nothing asked of the outside");
      assert.equal(tracedRisks(reply).length, 1);
    },
  );
});

test("the Worker's verdicts travel back as entries and are applied by the one-way rule", async () => {
  await withWorker(
    (_step, input) =>
      Response.json({ value: (input as Array<{ id: string }>).map((q) => [q.id, { protects: true, reason: "It turns the value into a number." }]) }),
    async (asked) => {
      const reply = await handleReview(request({ cleanerJudge: { name: "claude:test" } }), runSecurityReview);
      assert.deepEqual(asked.map((a) => a.step), ["judge"]);
      const question = (asked[0]!.input as Array<Record<string, unknown>>)[0]!;
      assert.deepEqual(Object.keys(question).sort(), ["code", "feeds", "id", "name", "usedIn"], "only the question is sent");
      assert.equal(question.name, "toSafeId");
      assert.equal(tracedRisks(reply).length, 0, "softened");
      assert.ok(reply.type === "done" && reply.result.stats.cleaners?.working === 1);
      assert.ok(reply.type === "done" && reply.result.summary.unproven >= 1, "still listed as worth a look");
    },
  );
});

test("a refused, failed or malformed answer from the Worker leaves the finding in place", async () => {
  const answers: Array<[() => Response, "refused" | "failed" | "used"]> = [
    [() => Response.json({ error: "refused" }, { status: 502 }), "refused"],
    [() => Response.json({ error: "failed" }, { status: 403 }), "failed"],
    [() => new Response("not json", { status: 200 }), "failed"],
    // Well-formed JSON of the wrong shape: no verdicts, so nothing changes.
    [() => Response.json({ value: [["q1", { protects: "yes" }], "junk", ["q1"]] }), "used"],
    [() => Response.json({ value: { q1: { protects: true, reason: "x" } } }), "used"],
  ];
  for (const [answer, status] of answers) {
    await withWorker(answer, async () => {
      const reply = await handleReview(request({ cleanerJudge: { name: "claude:test" } }), runSecurityReview);
      assert.equal(tracedRisks(reply).length, 1, `the finding stays (${status})`);
      assert.ok(reply.type === "done" && reply.result.stats.cleaners?.status === status);
      assert.ok(reply.type === "done" && reply.result.stats.cleaners?.working === 0);
    });
  }
});
