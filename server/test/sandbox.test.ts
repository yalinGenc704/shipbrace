import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
  ProposerRefusedError,
  runSecurityReview,
  snapshotFromFiles,
  type AttackProposer,
  type CleanerJudge,
  type CleanerQuestion,
} from "@shipbrace/guardrails";
import { createSandbox, DEFAULT_SANDBOX_LIMITS, ReviewStoppedError } from "../src/sandbox/sandbox.ts";

const fixture = (name: string) => fileURLToPath(new URL(`./sandbox-fixtures/${name}.ts`, import.meta.url));
const quiet = () => {};

const VULNERABLE = snapshotFromFiles([
  {
    path: "server/src/api.ts",
    content: [
      'import { Hono } from "hono";',
      "const app = new Hono();",
      'app.get("/api/reports/:id", async (c) => {',
      '  const id = c.req.param("id");',
      "  return c.json(await db.query(`SELECT * FROM reports WHERE id = ${id}`));",
      "});",
    ].join("\n"),
  },
]);

const withoutTiming = (r: Awaited<ReturnType<typeof runSecurityReview>>) => ({ ...r, stats: { ...r.stats, durationMs: 0 } });

// --- the same review, sealed off ------------------------------------------------------

test("a sealed review finds exactly what an ordinary one does", async () => {
  const sealed = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(VULNERABLE);
  assert.deepEqual(withoutTiming(sealed), withoutTiming(await runSecurityReview(VULNERABLE)));
  assert.ok(sealed.summary.high > 0);
});

test("the AI step is answered from outside, and waiting for it is not counted as work", async () => {
  const asked: unknown[] = [];
  const proposer: AttackProposer = {
    name: "slow-model",
    propose: async (context) => {
      asked.push(context);
      await new Promise((resolve) => setTimeout(resolve, 5_000));
      return [];
    },
  };
  // A four-second work limit, and an AI that takes five. The limit leaves
  // room for the review's own work on a busy machine: at one second, starting
  // the sealed process and running every check sometimes used it all up.
  const review = await createSandbox({ ...DEFAULT_SANDBOX_LIMITS, workMs: 4_000 }, undefined, quiet)(VULNERABLE, { proposer });

  assert.equal(asked.length, 1);
  assert.equal(review.stats.model.status, "used");
  assert.equal(review.stats.model.name, "slow-model");
});

test("a refusal from the AI reaches the review as a refusal, not as a pass", async () => {
  const proposer: AttackProposer = {
    name: "refusing-model",
    propose: () => Promise.reject(new ProposerRefusedError("policy")),
  };
  const review = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(VULNERABLE, { proposer });
  assert.equal(review.stats.model.status, "refused");
  assert.ok(review.summary.high > 0, "the rules' findings stand");
});

test("the package lookup is answered from outside too", async () => {
  const snapshot = snapshotFromFiles([
    { path: "package.json", content: JSON.stringify({ name: "demo", dependencies: { hono: "4.6.0" } }) },
    {
      path: "package-lock.json",
      content: JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "demo" },
          "node_modules/hono": { version: "4.6.0", resolved: "https://registry.npmjs.org/hono/-/hono-4.6.0.tgz" },
        },
      }),
    },
  ]);
  const sent: unknown[] = [];
  const vulnerabilities = { notice: "test notice", lookup: async (deps: unknown) => (sent.push(deps), new Map()) };

  const review = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(snapshot, { vulnerabilities });
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === "components/known-vulnerabilities");
  assert.equal(sent.length, 1);
  assert.equal(item?.status, "pass");
  assert.equal(item?.notice, "test notice");
});

// --- the AI's reading of the app's own cleaning functions ----------------------------

/** A home-made cleaner the rules trust by its name, and one they do not see. */
const cleanerApp = (cleaner: string, use: string) =>
  snapshotFromFiles([
    {
      path: "server/src/index.ts",
      content: ['import { Hono } from "hono";', "const app = new Hono();", cleaner, 'app.get("/x", async (c) => {', ...use.split("\n"), "});"].join("\n"),
    },
  ]);
const BROKEN = cleanerApp(
  "function escapeSql(s) { return s.replace(\"'\", \"''\"); }",
  '  const name = escapeSql(c.req.query("name"));\n  return c.json(await db.query(`SELECT * FROM users WHERE name = \'${name}\'`));',
);
const WORKING = cleanerApp(
  "const toSafeId = (v) => parseInt(v, 10);",
  '  const id = toSafeId(c.req.query("id"));\n  return c.json(await db.query(`SELECT * FROM orders WHERE id = ${id}`));',
);
const scripted = (protects: boolean, asked: CleanerQuestion[][] = []): CleanerJudge => ({
  name: "scripted",
  judge: async (questions) => {
    asked.push(questions);
    return new Map(questions.map((q) => [q.id, { protects, reason: "Scripted reason." }]));
  },
});
const tracedRisks = (review: Awaited<ReturnType<typeof runSecurityReview>>) =>
  review.modules.flatMap((m) => m.items.flatMap((i) => i.risks)).filter((r) => r.id.startsWith("taint/"));

test("the cleaner step is answered from outside, once, and gives what an ordinary review gives", async () => {
  const asked: CleanerQuestion[][] = [];
  const sealed = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(BROKEN, { cleanerJudge: scripted(false, asked) });
  assert.equal(asked.length, 1, "asked once");
  assert.match(asked[0]![0]!.code, /function escapeSql/, "the function's own code crossed the wall");
  assert.equal(tracedRisks(sealed)[0]?.confirmedBy, "cleaner-check");
  assert.deepEqual(sealed.stats.cleaners, { status: "used", name: "scripted", asked: 1, broken: 1, working: 0 });
  const ordinary = await runSecurityReview(BROKEN, { cleanerJudge: scripted(false) });
  assert.deepEqual(withoutTiming(sealed), withoutTiming(ordinary));
});

test("an AI saying a cleaner works softens the finding and never removes it, sealed as well", async () => {
  const before = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(WORKING);
  assert.equal(tracedRisks(before).length, 1);
  const after = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(WORKING, { cleanerJudge: scripted(true) });
  assert.equal(tracedRisks(after).length, 0);
  const leads = after.modules.flatMap((m) => m.items.flatMap((i) => i.unproven));
  assert.ok(leads.some((l) => l.id.startsWith("cleaner/") && /toSafeId/.test(l.what)), "still on the page, as worth a look");
});

test("without the cleaner step switched on, nothing is asked and the rules' answer stands", async () => {
  const sealed = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(BROKEN);
  assert.equal(sealed.stats.cleaners, undefined);
  assert.equal(tracedRisks(sealed).length, 0);
});

test("a cleaner judge that declines or fails leaves the rules' answer, and the review says so", async () => {
  const refusing: CleanerJudge = { name: "refusing", judge: () => Promise.reject(new ProposerRefusedError("policy")) };
  const failing: CleanerJudge = { name: "failing", judge: () => Promise.reject(new Error("network")) };
  for (const [cleanerJudge, status] of [[refusing, "refused"], [failing, "failed"]] as const) {
    const review = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(WORKING, { cleanerJudge });
    assert.equal(review.stats.cleaners?.status, status);
    assert.equal(tracedRisks(review).length, 1, "the finding stays a finding");
  }
});

test("a process asking for the cleaner step when the review was not given it is stopped", async () => {
  await assert.rejects(
    createSandbox(DEFAULT_SANDBOX_LIMITS, fixture("uninvited"), quiet)(VULNERABLE),
    (error: unknown) => error instanceof ReviewStoppedError && error.reason === "crash",
  );
  // Even with a proposer and a lookup switched on: each step is its own permission.
  let calls = 0;
  const proposer: AttackProposer = { name: "m", propose: async () => (calls++, []) };
  await assert.rejects(createSandbox(DEFAULT_SANDBOX_LIMITS, fixture("uninvited"), quiet)(VULNERABLE, { proposer }), ReviewStoppedError);
  assert.equal(calls, 0);
});

test("a process asking for a step that does not exist is stopped, not given the package lookup", async () => {
  let calls = 0;
  const vulnerabilities = { notice: "n", lookup: async () => (calls++, new Map()) };
  await assert.rejects(
    createSandbox(DEFAULT_SANDBOX_LIMITS, fixture("unknown-step"), quiet)(VULNERABLE, { vulnerabilities }),
    ReviewStoppedError,
  );
  assert.equal(calls, 0);
});

// --- the walls ----------------------------------------------------------------------

test("a review that never finishes is stopped at its time limit", async () => {
  const started = Date.now();
  await assert.rejects(
    createSandbox({ ...DEFAULT_SANDBOX_LIMITS, workMs: 500 }, fixture("hang"), quiet)(VULNERABLE),
    (error: unknown) => error instanceof ReviewStoppedError && error.reason === "time",
  );
  assert.ok(Date.now() - started < 5_000);
});

test("a review that eats memory is stopped at its memory limit", async () => {
  await assert.rejects(
    createSandbox({ ...DEFAULT_SANDBOX_LIMITS, memoryMb: 64 }, fixture("memory"), quiet)(VULNERABLE),
    (error: unknown) => error instanceof ReviewStoppedError && error.reason === "memory",
  );
});

test("a crash costs one review, and the next one runs normally", async () => {
  await assert.rejects(
    createSandbox(DEFAULT_SANDBOX_LIMITS, fixture("crash"), quiet)(VULNERABLE),
    (error: unknown) => error instanceof ReviewStoppedError && error.reason === "crash",
  );
  const next = await createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)(VULNERABLE);
  assert.ok(next.summary.high > 0);
});

test("a process that asks for more than the pipeline would is stopped", async () => {
  let calls = 0;
  const proposer: AttackProposer = { name: "m", propose: async () => (calls++, []) };
  await assert.rejects(
    createSandbox(DEFAULT_SANDBOX_LIMITS, fixture("greedy"), quiet)(VULNERABLE, { proposer }),
    ReviewStoppedError,
  );
  assert.ok(calls <= 1);
});

test("inside, there are no secrets, no network, and nothing to read but ShipBrace's own code", async () => {
  process.env.AEGIS_TEST_SECRET = "must-not-cross";
  const report = (await createSandbox(DEFAULT_SANDBOX_LIMITS, fixture("snoop"), quiet)(VULNERABLE)) as unknown as Record<string, unknown>;
  delete process.env.AEGIS_TEST_SECRET;

  // macOS adds its text-encoding setting to every process it starts; it is
  // the system's, not the server's.
  const env = (report.env as string[]).filter((name) => name !== "__CF_USER_TEXT_ENCODING");
  assert.deepEqual(env, [], "nothing inherited from the server's environment");
  assert.equal(report.readProjectFile, "denied");
  assert.equal(report.readEnvFile, "denied", "the folder holding .env and the App's key is off limits");
  assert.equal(report.readHome, "denied");
  assert.equal(report.readSystem, "denied");
  assert.equal(report.write, "denied");
  assert.equal(report.run, "denied");
  assert.equal(report.network, "denied");
  assert.equal(report.socket, "denied");
  assert.equal(report.readOwnPackages, "allowed", "it can still load the code it runs");
  assert.ok(!existsSync(fixture("escaped").replace(/\.ts$/, ".txt")));
});

test("reviews beyond the limit wait their turn instead of all running at once", async () => {
  let peak = 0;
  let now = 0;
  const proposer: AttackProposer = {
    name: "m",
    propose: async () => {
      peak = Math.max(peak, ++now);
      await new Promise((resolve) => setTimeout(resolve, 200));
      now--;
      return [];
    },
  };
  const review = createSandbox({ ...DEFAULT_SANDBOX_LIMITS, concurrency: 2 }, undefined, quiet);
  await Promise.all([1, 2, 3, 4].map(() => review(VULNERABLE, { proposer })));
  assert.equal(peak, 2);
});

test("when too many reviews are waiting, more are refused plainly instead of piling up", async () => {
  let release!: () => void;
  const gate = new Promise<void>((resolve) => (release = resolve));
  const proposer: AttackProposer = { name: "m", propose: async () => (await gate, []) };
  const review = createSandbox({ ...DEFAULT_SANDBOX_LIMITS, concurrency: 1, maxWaiting: 1 }, undefined, quiet);

  const running = review(VULNERABLE, { proposer });
  const waiting = review(VULNERABLE, { proposer });
  await assert.rejects(
    review(VULNERABLE, { proposer }),
    (error: unknown) => error instanceof ReviewStoppedError && error.reason === "busy",
  );
  release();
  await Promise.all([running, waiting]);
});
