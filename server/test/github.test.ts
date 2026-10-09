import assert from "node:assert/strict";
import { createHmac, createVerify, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { runSecurityReview } from "@aegis/guardrails";
import { appJwt, verifyWebhookSignature } from "../src/github/auth.ts";
import { handleWebhook, type WebhookDeps } from "../src/github/webhook.ts";
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
function fakeGitHub(files: Record<string, string | Buffer>, extraTree: Array<{ path: string; size: number }> = []) {
  const calls: Array<{ method: string; path: string; body?: any }> = [];
  const blobs = new Map(Object.entries(files).map(([path, content], i) => [`blob${i}`, { path, content }]));

  const fetchImpl = (async (url: string, init?: { method?: string; body?: string }) => {
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
  }) as typeof fetch;

  return { fetchImpl, calls };
}

function deps(fetchImpl: typeof fetch, over: Partial<WebhookDeps> = {}): WebhookDeps & { done: Promise<void>[] } {
  const done: Promise<void>[] = [];
  return {
    secret: SECRET,
    credentials: { appId: "12345", privateKey: PEM },
    review: (snapshot) => runSecurityReview(snapshot),
    schedule: (task) => void done.push(task()),
    fetchImpl,
    log: () => {},
    done,
    ...over,
  };
}

const push = (over: Record<string, unknown> = {}) =>
  JSON.stringify({
    after: SHA,
    repository: { id: 4242, name: "shop", owner: { login: "murat" } },
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

  const patches = github.calls.filter((c) => c.method === "PATCH").map((c) => c.body);
  const output = patches.find((p) => p.output)?.output;
  const final = patches.at(-1);
  assert.equal(final.status, "completed");
  assert.equal(final.conclusion, "failure", "a proven high risk fails the check");
  assert.match(output.title, /high-risk problem/);
  assert.match(output.title, /for you to check/, "a tick never reads as 'secure'");
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
    publicUrl: "https://aegis.example",
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
  assert.equal(withOutput.details_url, `https://aegis.example/reviews/${"R".repeat(24)}`);
  assert.ok(withOutput.output.summary.startsWith(`**[Open the full report](https://aegis.example/reviews/${"R".repeat(24)})**`));
  assert.ok(withOutput.output.summary.includes(`https://aegis.example/history/${"H".repeat(24)}`));
});

test("if the history cannot be saved, the check is still posted in full, without links", async () => {
  const github = fakeGitHub({ "server/src/api.ts": VULNERABLE });
  const logged: string[] = [];
  const d = deps(github.fetchImpl, {
    history: { record: () => Promise.reject(new Error("database down")) },
    publicUrl: "https://aegis.example",
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
  const body = push({ repository: { name: "shop", owner: { login: "murat" } } });
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
