import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { ProposerRefusedError, runSecurityReview, snapshotFromFiles, type AttackProposer } from "@shipbrace/guardrails";
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
      await new Promise((resolve) => setTimeout(resolve, 1_500));
      return [];
    },
  };
  // A one-second work limit, and an AI that takes a second and a half.
  const review = await createSandbox({ ...DEFAULT_SANDBOX_LIMITS, workMs: 1_000 }, undefined, quiet)(VULNERABLE, { proposer });

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
