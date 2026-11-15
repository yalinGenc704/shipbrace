import assert from "node:assert/strict";
import { createHmac, createVerify, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { runSecurityReview, snapshotFromFiles } from "@shipbrace/guardrails";
import { appJwt, verifyWebhookSignature } from "../src/github/auth.ts";
import { handleWebhook, type PushJob, reviewPush, type ReviewDeps, type WebhookDeps } from "../src/github/webhook.ts";
import { ReviewStoppedError } from "../src/sandbox/sandbox.ts";

const SECRET = "a-long-random-webhook-secret-for-tests";
const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const PEM = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
const SHA = "a".repeat(40);

const sign = (body: string) => `sha256=${createHmac("sha256", SECRET).update(body).digest("hex")}`;

const VULNERABLE = [
  'import { Hono } from "hono";',
  "const app = new Hono();",
  'app.get("/api/reports/:id", async (c) => {',
  '  const id = c.req.param("id");',
  "  return c.json(await db.query(`SELECT * FROM reports WHERE id = ${id}`));",
  "});",
].join("\n");

/** A stand-in for GitHub's API that records every call made to it. */
function fakeGitHub(
  files: Record<string, string | Buffer>,
  extraTree: Array<{ path: string; size: number }> = [],
  /** GitHub's hourly allowance left after the nth call (1-based); omitted, no allowance headers are sent. */
  remainingAfter?: (n: number) => number,
  hour: { limit?: number; reset?: number } = {},
) {
  const calls: Array<{ method: string; path: string; body?: any }> = [];
  const blobs = new Map(Object.entries(files).map(([path, content], i) => [`blob${i}`, { path, content }]));

  const answer = async (url: string, init?: { method?: string; body?: string }): Promise<Response> => {
    const response = await route(url, init);
    if (!remainingAfter) return response;
    const headers = new Headers(response.headers);
    headers.set("x-ratelimit-remaining", String(Math.max(0, remainingAfter(calls.length))));
    headers.set("x-ratelimit-reset", String(hour.reset ?? RESET));
    if (hour.limit !== undefined) headers.set("x-ratelimit-limit", String(hour.limit));
    return new Response(response.body, { status: response.status, headers });
  };

  const route = (async (url: string, init?: { method?: string; body?: string }) => {
    const path = url.replace("https://api.github.com", "");
    const method = init?.method ?? "GET";
    calls.push({ method, path, ...(init?.body ? { body: JSON.parse(init.body) } : {}) });

    if (path === "/app/installations/7/access_tokens") return Response.json({ token: "ghs_installation" });
    if (method === "POST" && path.endsWith("/check-runs")) return Response.json({ id: 99 });
    if (method === "PATCH") return Response.json({});
    if (path.includes("/git/trees/")) {
      return Response.json({
        truncated: false,
        tree: [
          ...[...blobs].map(([sha, b]) => ({ path: b.path, type: "blob", sha, size: Buffer.byteLength(b.content) })),
          ...extraTree.map((e, i) => ({ path: e.path, type: "blob", sha: `extra${i}`, size: e.size })),
        ],
      });
    }
    const blob = blobs.get(path.split("/").pop()!);
    if (blob) return Response.json({ encoding: "base64", content: Buffer.from(blob.content).toString("base64") });
    return new Response("not found", { status: 404 });
  });

  return { fetchImpl: answer as unknown as typeof fetch, calls };
}

function deps(
  fetchImpl: typeof fetch,
  over: Partial<ReviewDeps> = {},
): WebhookDeps & ReviewDeps & { done: Promise<void>[] } {
  const done: Promise<void>[] = [];
  const d: WebhookDeps & ReviewDeps & { done: Promise<void>[] } = {
    secret: SECRET,
    credentials: { appId: "12345", privateKey: PEM },
    review: (snapshot) => runSecurityReview(snapshot),
    // The job runs inline, exactly as the laptop server runs it after answering.
    schedule: (job) => void done.push(reviewPush(d, job)),
    fetchImpl,
    log: () => {},
    done,
    ...over,
  };
  return d;
}

const push = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    after: SHA,
    repository: { id: 4242, name: "shop", owner: { login: "ada" } },
    installation: { id: 7 },
    ...over,
  });

// --- proving who is talking -----------------------------------------------------

test("a correctly signed body is accepted and anything else refused", () => {
  const body = push();
  assert.equal(verifyWebhookSignature(SECRET, body, sign(body)), true);
  assert.equal(verifyWebhookSignature(SECRET, `${body} `, sign(body)), false, "one changed byte");
  assert.equal(verifyWebhookSignature(SECRET, body, undefined), false);
  assert.equal(verifyWebhookSignature(SECRET, body, "sha256=abc"), false, "wrong length");
  assert.equal(verifyWebhookSignature("another-secret-entirely-xxxxxxx", body, sign(body)), false);
});

test("the App's token is signed so GitHub can check it, and short-lived", () => {
  const token = appJwt("12345", PEM, 1_000_000);
  const [header, payload, signature] = token.split(".");
  const verified = createVerify("RSA-SHA256").update(`${header}.${payload}`)
    .verify(publicKey, Buffer.from(signature!, "base64url"));
  assert.ok(verified);
  const claims = JSON.parse(Buffer.from(payload!, "base64url").toString());
  assert.equal(claims.iss, "12345");
  assert.ok(claims.exp - claims.iat <= 600, "GitHub allows at most ten minutes");
});

test("an unsigned message is refused and GitHub is never contacted", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = deps(github.fetchImpl);
  const result = await handleWebhook(d, { signature: "sha256=forged", event: "push" }, push());
  assert.equal(result.status, 401);
  assert.equal(d.done.length, 0);
  assert.equal(github.calls.length, 0);
});

test("a deleted branch is acknowledged without a review", async () => {
  const github = fakeGitHub({});
  const d = deps(github.fetchImpl);
  const body = push({ after: "0".repeat(40), deleted: true });
  const result = await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  assert.equal(result.status, 204);
  assert.equal(d.done.length, 0);
});

// --- the whole round trip ----------------------------------------------------------

test("a push is reviewed and the result posted back as a check, in plain words", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = deps(github.fetchImpl);
  const body = push();

  const result = await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  assert.equal(result.status, 202, "GitHub is answered before the review runs");
  await Promise.all(d.done);

  const started = github.calls.find((c) => c.method === "POST" && c.path.endsWith("/check-runs"));
  assert.equal(started?.body.head_sha, SHA);
  assert.equal(started?.body.status, "in_progress");

  // The token is asked for this one repository, to read code and write the check only.
  const minted = github.calls.find((c) => c.path === "/app/installations/7/access_tokens");
  assert.deepEqual(minted?.body, { repository_ids: [4242], permissions: { contents: "read", checks: "write", metadata: "read" } });

  const patches = github.calls.filter((c) => c.method === "PATCH").map((c) => c.body);
  const output = patches.find((p) => p.output)?.output;
  const final = patches.at(-1);
  assert.equal(final.status, "completed");
  assert.equal(final.conclusion, "failure", "a proven high risk fails the check");
  assert.match(output.title, /high-risk problem/);
  assert.match(output.title, /for you to check/, "a tick never reads as 'secure'");
  assert.match(output.title, /good-practice question/, "the checklist is left for the user too");
  assert.match(output.summary, /Why this matters/);

  const note = output.annotations.find((a: any) => a.path === "server/src/api.ts" && a.annotation_level === "failure");
  assert.equal(note?.start_line, 5);
  for (const jargon of ["taint", "sink", "sanitiz", "cwe", "payload"]) {
    assert.ok(!JSON.stringify(output).toLowerCase().includes(jargon), `leaked jargon: ${jargon}`);
  }
});

test("hostile repositories cannot make the server read what it should not", async () => {
  const github = fakeGitHub(
    {
      "server/src/api.ts": VULNERABLE,
      "node_modules/evil/index.ts": 'const k = "sk-aaaaaaaaaaaaaaaaaaaaaa";',
      "assets/logo.ts": Buffer.from([0x00, 0x01, 0x02]),
    },
    [{ path: "server/src/huge.ts", size: 50 * 1024 * 1024 }],
  );
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const fetched = github.calls.filter((c) => c.path.includes("/git/blobs/")).map((c) => c.path.split("/").pop());
  assert.ok(!fetched.includes("blob1"), "skipped folders are never downloaded");
  assert.ok(!fetched.includes("extra0"), "oversized files are never downloaded");
  const output = github.calls.filter((c) => c.method === "PATCH").find((c) => c.body.output)?.body.output;
  assert.match(output.summary, /Not everything was read/);
});

test("a review that crashes is reported as not completed, never as a pass", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = deps(github.fetchImpl, { review: () => Promise.reject(new Error("boom")) });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.status, "completed");
  assert.equal(final.conclusion, "neutral");
  assert.match(final.output.title, /could not be completed/);
  assert.ok(!JSON.stringify(final).includes("boom"), "internal error text stays in the log");
});

// --- review history ----------------------------------------------------------------

test("a saved review is linked from the check, and the links lead to it", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const saved: any[] = [];
  const d = deps(github.fetchImpl, {
    history: { record: async (review) => (saved.push(review), { reviewId: "R".repeat(24), historyId: "H".repeat(24) }) },
    publicUrl: "https://shipbrace.example",
  });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  assert.equal(saved.length, 1);
  assert.equal(saved[0].githubId, 4242, "kept by GitHub's id, which survives renames");
  assert.equal(saved[0].commitSha, SHA);
  assert.equal(saved[0].conclusion, "failure");
  assert.ok(saved[0].result.summary.high > 0);

  const withOutput = github.calls.filter((c) => c.method === "PATCH").find((c) => c.body.output)?.body;
  assert.equal(withOutput.details_url, `https://shipbrace.example/reviews/${"R".repeat(24)}`);
  assert.ok(withOutput.output.summary.startsWith(`**[Open the full report](https://shipbrace.example/reviews/${"R".repeat(24)})**`));
  assert.ok(withOutput.output.summary.includes(`https://shipbrace.example/history/${"H".repeat(24)}`));
});

test("if the history cannot be saved, the check is still posted in full, without links", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const logged: string[] = [];
  const d = deps(github.fetchImpl, {
    history: { record: () => Promise.reject(new Error("database down")) },
    publicUrl: "https://shipbrace.example",
    log: (message) => void logged.push(message),
  });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const patches = github.calls.filter((c) => c.method === "PATCH").map((c) => c.body);
  const withOutput = patches.find((p) => p.output);
  assert.equal(withOutput.details_url, undefined);
  assert.match(withOutput.output.title, /high-risk problem/, "the risks are not withheld");
  assert.equal(patches.at(-1).conclusion, "failure");
  assert.ok(logged.some((m) => m.startsWith("could not save the review")));
});

test("a push without GitHub's repository id is refused", async () => {
  const github = fakeGitHub({});
  const d = deps(github.fetchImpl);
  const body = push({ repository: { name: "shop", owner: { login: "ada" } } });
  const result = await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  assert.equal(result.status, 400);
  assert.equal(d.done.length, 0);
});

test("a review stopped by its time limit says so on the check, in plain words", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = deps(github.fetchImpl, { review: () => Promise.reject(new ReviewStoppedError("time")) });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.conclusion, "neutral", "never a pass");
  assert.match(final.output.summary, /longer than its time limit/);
  assert.match(final.output.summary, /Nothing in this commit was checked/);
});

test("a review over the daily limit says so, without suggesting an immediate retry", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = deps(github.fetchImpl, { review: () => Promise.reject(new ReviewStoppedError("limit")) });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.conclusion, "neutral", "never a pass");
  assert.match(final.output.summary, /daily review limit has been reached/);
  assert.match(final.output.summary, /Try again tomorrow\.$/);
  assert.doesNotMatch(final.output.summary, /Push again/);
});

// --- GitHub's hourly allowance (a 5,000-file review spun for ever on 2026-11-14) ------

// Half an hour from now, on the minute, as GitHub sends it (seconds since 1970).
const RESET = Math.floor(Date.now() / 60_000) * 60 + 1800;
const RESET_HHMM = new Date(RESET * 1000).toISOString().slice(11, 16);

const MANY = Object.fromEntries(Array.from({ length: 30 }, (_, i) => [`src/file${i}.ts`, `export const n${i} = ${i};`]));

test("too little of GitHub's hourly allowance: nothing is read, and the check says when to push again", async () => {
  // 40 left after the file list: 30 files plus the 20 kept back do not fit.
  const github = fakeGitHub(MANY, [], () => 40);
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  assert.equal(github.calls.filter((c) => c.path.includes("/git/blobs/")).length, 0, "no file read");
  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.status, "completed", "never left spinning");
  assert.equal(final.conclusion, "neutral", "never a pass");
  assert.equal(final.output.title, "Too many files to read right now");
  assert.match(final.output.summary, /needs about 50; 40 are left right now/);
  assert.match(final.output.summary, /Nothing in this commit was checked/);
  assert.ok(final.output.summary.endsWith(`Push again after ${RESET_HHMM} UTC.`));
});

test("more files than a whole hour allows: the check says so, without a pointless push-again time", async () => {
  const github = fakeGitHub(MANY, [], () => 40, { limit: 45 });
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.status, "completed");
  assert.equal(final.conclusion, "neutral");
  assert.equal(final.output.title, "Too many files to read");
  assert.match(final.output.summary, /more than the 45 GitHub allows ShipBrace in an hour/);
  assert.match(final.output.summary, /cannot be reviewed yet\.$/);
  assert.doesNotMatch(final.output.summary, /Push again/);
});

test("an implausible reset time from GitHub is not believed, and the review runs", async () => {
  const github = fakeGitHub(MANY, [], () => 40, { reset: 99_999_999_999 });
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  assert.equal(github.calls.filter((c) => c.path.includes("/git/blobs/")).length, 30);
  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.status, "completed");
  assert.notEqual(final.output?.title, "Too many files to read right now");
});

test("enough allowance: the review runs as before", async () => {
  const github = fakeGitHub({ ...MANY, "server/src/api.ts": VULNERABLE }, [], () => 4_000);
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  assert.equal(github.calls.filter((c) => c.path.includes("/git/blobs/")).length, 31);
  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.conclusion, "failure", "the proven risk is reported");
});

test("an allowance spent by something else mid-read stops the reading and still reports", async () => {
  // Plenty at first, then another review on the same installation takes the rest.
  const github = fakeGitHub(MANY, [], (n) => (n < 6 ? 4_000 : 25));
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  assert.ok(github.calls.filter((c) => c.path.includes("/git/blobs/")).length < 30, "stopped early");
  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.status, "completed");
  assert.equal(final.output.title, "Too many files to read right now");
});

test("with the hour nearly spent, the check's notes are cut short but its result is posted", async () => {
  // Many proven risks, so many notes; one request left after the first batch.
  const routes = Array.from({ length: 60 }, (_, i) => `app.get("/r${i}", async (c) => c.json(await db.query(\`SELECT * FROM t WHERE id = \${c.req.query("id")}\`)));`);
  const app = ['import { Hono } from "hono";', "const app = new Hono();", ...routes].join("\n");
  let firstPatch = 0;
  const github = fakeGitHub({ "server/src/api.ts": app }, [], (n) => {
    if (firstPatch === 0 && github.calls[n - 1]?.method === "PATCH") firstPatch = n;
    return firstPatch > 0 ? 2 : 4_000;
  });
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const patches = github.calls.filter((c) => c.method === "PATCH");
  assert.equal(patches.length, 2, "one batch of notes, then the result");
  assert.equal(patches[0]!.body.output.annotations.length, 50);
  assert.equal(patches.at(-1)!.body.status, "completed");
  assert.equal(patches.at(-1)!.body.conclusion, "failure");
});

test("with the hour spent before any notes, the result alone is posted, carrying the title and summary", async () => {
  // Plenty while reading; then something else spends the hour during the review.
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE }, [], (n) => (n <= 3 ? 4_000 : 2));
  const d = deps(github.fetchImpl);
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const patches = github.calls.filter((c) => c.method === "PATCH");
  assert.equal(patches.length, 1, "only the result");
  assert.equal(patches[0]!.body.status, "completed");
  assert.equal(patches[0]!.body.conclusion, "failure");
  assert.match(patches[0]!.body.output.title, /\S/);
  assert.match(patches[0]!.body.output.summary, /\S/);
});

// --- the dashboard learns why a review stopped ---------------------------------------

test("a refused review tells the dashboard why, in the check's own words", async () => {
  const github = fakeGitHub(MANY, [], () => 40);
  const problems: unknown[] = [];
  const d = deps(github.fetchImpl, { recordProblem: async (p) => void problems.push(p) });
  const body = push({ sender: { id: 77 } });
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.deepEqual(problems, [{
    githubId: 4242, installationId: 7, ranBy: 77, commitSha: SHA,
    title: final.output.title, message: final.output.summary,
  }]);
});

test("a stopped review tells the dashboard too, and a failure to keep it never blocks the check", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = deps(github.fetchImpl, {
    review: () => Promise.reject(new ReviewStoppedError("time")),
    recordProblem: () => Promise.reject(new Error("database down")),
  });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);

  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.status, "completed");
  assert.match(final.output.summary, /longer than its time limit/);
});

test("a finished review does not tell the dashboard of a problem", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const problems: unknown[] = [];
  const d = deps(github.fetchImpl, { recordProblem: async (p) => void problems.push(p) });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);
  assert.deepEqual(problems, []);
});

test("when no check can even be started, the dashboard still learns the review stopped", async () => {
  const problems: Array<{ title: string }> = [];
  const refusing = (async () => new Response("no", { status: 500 })) as unknown as typeof fetch;
  const d = deps(refusing, { recordProblem: async (p) => void problems.push(p) });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);
  assert.equal(problems.length, 1);
  assert.equal(problems[0]?.title, "The review could not be completed");
});

test("a review whose report was saved is not reported as stopped, even if the check then fails", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const failingPatch = (async (url: string, init?: { method?: string }) =>
    init?.method === "PATCH" && github.calls.filter((c) => c.method === "PATCH").length === 0
      ? (github.calls.push({ method: "PATCH", path: "first" }), new Response("busy", { status: 502 }))
      : github.fetchImpl(url, init as RequestInit)) as unknown as typeof fetch;
  const problems: unknown[] = [];
  const d = deps(failingPatch, {
    history: { record: async () => ({ reviewId: "r".repeat(22), historyId: "h".repeat(22) }) },
    publicUrl: "https://app.example",
    recordProblem: async (p) => void problems.push(p),
  });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);
  assert.deepEqual(problems, [], "the dashboard has the saved report");
});

// --- the mark when an AI softened a finding -----------------------------------------

// Protective headers and a rate limit are in place, so the home-made cleaner
// is the only thing the review has to say about this app.
const HOMEMADE = [
  'import { Hono } from "hono";',
  'import { secureHeaders } from "hono/secure-headers";',
  'import { rateLimiter } from "hono-rate-limiter";',
  "const app = new Hono();",
  'app.use("*", secureHeaders());',
  'app.use("*", rateLimiter({ windowMs: 60000, limit: 60 }));',
  "const toSafeId = (v) => parseInt(v, 10);",
  'app.get("/orders", requireUser, async (c) => {',
  '  const id = toSafeId(c.req.query("id"));',
  "  return c.json(await db.query(`SELECT * FROM orders WHERE id = ${id}`));",
  "});",
].join("\n");
const saysItWorks = { name: "scripted", judge: async (questions: Array<{ id: string }>) => new Map(questions.map((q) => [q.id, { protects: true, reason: "It turns the value into a number." }])) };

async function finalCheck(review: ReviewDeps["review"]) {
  const github = fakeGitHub({ "server/src/api.ts": HOMEMADE });
  const d = deps(github.fetchImpl, { review });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);
  const patches = github.calls.filter((c) => c.method === "PATCH").map((c) => c.body);
  return { final: patches.at(-1), output: patches.find((p) => p.output)?.output };
}

test("a finding an AI moved to 'worth a look' never gives a green check", async () => {
  // The rules alone: one proven high risk through the home-made cleaner.
  const rules = await finalCheck((snapshot) => runSecurityReview(snapshot));
  assert.equal(rules.final.conclusion, "failure");

  // The AI says the cleaner works: no proven problem is left, but the mark is
  // neutral and the title and summary say an opinion is waiting.
  const softened = await finalCheck((snapshot) => runSecurityReview(snapshot, { cleanerJudge: saysItWorks }));
  assert.equal(softened.final.conclusion, "neutral", "an AI's opinion is not a pass");
  assert.match(softened.output.title, /^1 finding an AI thinks is safe, for you to confirm/);
  assert.doesNotMatch(softened.output.title, /No proven problems/);
  assert.match(softened.output.summary, /An AI's opinion is waiting for you to confirm/);
  assert.match(softened.output.summary, /not marked as passed/);
  // The line itself still carries a note, naming the function.
  const note = softened.output.annotations.find((a: { title: string }) => a.title === "Worth a look, not proven");
  assert.match(note?.message ?? "", /toSafeId/);
});

test("when the AI could not read the cleaning functions, the check says so and keeps the finding", async () => {
  const failing = { name: "failing", judge: () => Promise.reject(new Error("network")) };
  const { final, output } = await finalCheck((snapshot) => runSecurityReview(snapshot, { cleanerJudge: failing }));
  assert.equal(final.conclusion, "failure", "the rules' finding stands");
  assert.match(output.summary, /could not be reached to read your app's own cleaning functions/);
});

test("every sentence in the check's summary is escaped, whoever wrote it", async () => {
  const { checkOutput } = await import("../src/github/report.ts");
  const review = await runSecurityReview(snapshotFromFiles([{ path: "server/src/api.ts", content: VULNERABLE }]));
  // As if the sealed reviewer had been taken over and wrote these itself.
  const item = review.modules.flatMap((m) => m.items).find((i) => i.risks.length > 0)!;
  item.risks[0]!.impact = "See [the fix](https://evil.example) ![x](https://evil.example/p.png)";
  item.risks[0]!.fix = "Run <script>alert(1)</script> now";
  item.notice = "Checked by [us](https://evil.example)";
  const { summary } = checkOutput(review);
  assert.doesNotMatch(summary, /(?<!\\)\]\(https:\/\/evil\.example/, "no working link or image");
  assert.doesNotMatch(summary, /<script>/);
  assert.match(summary, /\\\[the fix\\\]/);

  // Three backticks do not open a span the escaping never sees, and a bare
  // address does not become a link on its own.
  item.risks[0]!.impact = "```[the fix](https://evil.example)` and see https://evil.example or www.evil.example";
  item.risks[0]!.fix = "```<a href=https://evil.example>fix</a>`";
  const whole = checkOutput(review).summary;
  assert.doesNotMatch(whole, /```/);
  // What is left inside a code span shows as plain code; the rest is checked.
  const again = whole.replace(/`[^`]*`/g, "CODE");
  assert.doesNotMatch(again, /(?<!\\)\]\(/);
  assert.doesNotMatch(again, /https:\/\/evil/, "no bare address left for GitHub to link");
  assert.doesNotMatch(again, /\bwww\.evil/);
  // Ordinary report text reads as before.
  assert.match(again, /\*\*HIGH RISK\.\*\* Part of the web address on the page \/api\/reports\/:id/);
});

test("a large webhook is still accepted: the small limit is only for signed-in requests", async () => {
  const { MAX_WEBHOOK_BYTES } = await import("../../cloud/src/webhook-limit.ts");
  assert.ok(MAX_WEBHOOK_BYTES > 1024 * 1024);
});

test("with nothing softened, a clean review is still a pass", async () => {
  const github = fakeGitHub({ "server/src/api.ts": 'export const greeting = "hello";' });
  const d = deps(github.fetchImpl, { review: (snapshot) => runSecurityReview(snapshot, { cleanerJudge: saysItWorks }) });
  const body = push();
  await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  await Promise.all(d.done);
  const final = github.calls.filter((c) => c.method === "PATCH").at(-1)?.body;
  assert.equal(final.conclusion, "success");
});

// --- setup and uninstall ------------------------------------------------------------

test("pushes from an installation nobody has set up are not reviewed", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = deps(github.fetchImpl);
  const gated = { ...d, isSetUp: async (id: number) => id !== 7 };
  const body = push();
  const result = await handleWebhook(gated, { signature: sign(body), event: "push" }, body);
  assert.equal(result.status, 202);
  assert.equal(result.body.accepted, false);
  assert.equal(d.done.length, 0);
  assert.equal(github.calls.length, 0, "nothing was fetched or sent");
});

test("uninstalling deletes everything kept; removing repositories deletes theirs", async () => {
  const forgotten: Array<[number, number[] | "all"]> = [];
  const d = { ...deps(fakeGitHub({}).fetchImpl), forget: async (i: number, r: number[] | "all") => void forgotten.push([i, r]) };

  const uninstall = JSON.stringify({ action: "deleted", installation: { id: 7 } });
  assert.equal((await handleWebhook(d, { signature: sign(uninstall), event: "installation" }, uninstall)).status, 200);

  const removed = JSON.stringify({ action: "removed", installation: { id: 7 }, repositories_removed: [{ id: 41 }, { id: 42 }] });
  await handleWebhook(d, { signature: sign(removed), event: "installation_repositories" }, removed);

  const forged = JSON.stringify({ action: "deleted", installation: { id: 8 } });
  assert.equal((await handleWebhook(d, { signature: "sha256=forged", event: "installation" }, forged)).status, 401);

  assert.deepEqual(forgotten, [[7, "all"], [7, [41, 42]]], "and an unsigned uninstall deletes nothing");
});

test("a push remembers who pushed it, so only they and the repository's admins can open its report", async () => {
  const jobs: PushJob[] = [];
  const body = push({ sender: { id: 31 } });
  const result = await handleWebhook({ secret: SECRET, schedule: (job) => void jobs.push(job) }, { signature: sign(body), event: "push" }, body);
  assert.equal(result.status, 202);
  assert.equal(jobs[0]?.ranBy, 31);
});

test("a push to a repository with push reviews switched off is acknowledged and not reviewed", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const d = { ...deps(github.fetchImpl), reviewsPushes: async (id: number) => id !== 4242 };
  const body = push();
  const result = await handleWebhook(d, { signature: sign(body), event: "push" }, body);
  assert.equal(result.status, 202);
  assert.deepEqual(result.body, { accepted: false, reason: "Reviews of pushes are switched off for this repository." });
  assert.equal(github.calls.length, 0, "nothing posted on GitHub");
});
