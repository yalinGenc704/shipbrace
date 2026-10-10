import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { createServer, type Server } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { ProposerRefusedError, runSecurityReview, snapshotFromFiles, type AttackProposer } from "@shipbrace/guardrails";
import { send } from "../src/sandbox/channel.ts";
import { createRemoteReviewer } from "../src/sandbox/remote.ts";
import { serveReviews } from "../src/sandbox/reviewer.ts";
import { createSandbox, DEFAULT_SANDBOX_LIMITS, ReviewStoppedError } from "../src/sandbox/sandbox.ts";

/**
 * The server and the review container, talking over a real Unix socket. On a
 * hosted server they are two containers; here both ends run in this process.
 */
const dir = mkdtempSync(join(tmpdir(), "shipbrace-remote-"));
const servers: Server[] = [];
after(() => servers.forEach((s) => s.close()));

const quiet = () => {};
let n = 0;
function reviewer(review = createSandbox(DEFAULT_SANDBOX_LIMITS, undefined, quiet)) {
  const path = join(dir, `r${n++}.sock`);
  servers.push(serveReviews(path, review));
  return createRemoteReviewer(path, quiet);
}

/** A reviewer that has been taken over: it sends whatever `script` says. */
function hostile(script: (socket: import("node:net").Socket) => void) {
  const path = join(dir, `h${n++}.sock`);
  const server = createServer(script);
  server.listen(path);
  servers.push(server);
  return createRemoteReviewer(path, quiet);
}

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

test("a review in the review container finds exactly what an ordinary one does", async () => {
  await new Promise((resolve) => setTimeout(resolve, 50));
  const remote = await reviewer()(VULNERABLE);
  assert.deepEqual(withoutTiming(remote), withoutTiming(await runSecurityReview(VULNERABLE)));
});

test("the AI step and its refusals cross the channel", async () => {
  const review = reviewer();
  const used: AttackProposer = { name: "model", propose: async () => [] };
  const refusing: AttackProposer = { name: "model", propose: () => Promise.reject(new ProposerRefusedError("policy")) };
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.equal((await review(VULNERABLE, { proposer: used })).stats.model.status, "used");
  assert.equal((await review(VULNERABLE, { proposer: refusing })).stats.model.status, "refused");
});

test("why the container stopped a review reaches the check", async () => {
  const review = reviewer(() => Promise.reject(new ReviewStoppedError("busy")));
  await new Promise((resolve) => setTimeout(resolve, 50));
  await assert.rejects(review(VULNERABLE), (e: unknown) => e instanceof ReviewStoppedError && e.reason === "busy");
});

test("when the review container is not running, the review says so", async () => {
  const review = createRemoteReviewer(join(dir, "nobody-here.sock"), quiet);
  await assert.rejects(review(VULNERABLE), (e: unknown) => e instanceof ReviewStoppedError && e.reason === "unavailable");
});

// --- a taken-over container -------------------------------------------------------

test("a container asking for the AI twice is cut off", async () => {
  let calls = 0;
  const proposer: AttackProposer = { name: "m", propose: async () => (calls++, []) };
  const review = hostile((socket) => {
    send(socket, { type: "ask", id: 0, step: "propose", input: {} }, "json");
    send(socket, { type: "ask", id: 1, step: "propose", input: {} }, "json");
  });
  await new Promise((resolve) => setTimeout(resolve, 50));
  await assert.rejects(review(VULNERABLE, { proposer }), ReviewStoppedError);
  assert.ok(calls <= 1);
});

test("a container sending an oversized message is cut off before it is read", async () => {
  const review = hostile((socket) => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(0xffffffff);
    socket.write(header);
  });
  await new Promise((resolve) => setTimeout(resolve, 50));
  await assert.rejects(review(VULNERABLE), (e: unknown) => e instanceof ReviewStoppedError && e.reason === "crash");
});

test("a container cannot invent a stop reason or a malformed result", async () => {
  const inventing = hostile((socket) => send(socket, { type: "stopped", reason: "all-clear" }, "json"));
  const malformed = hostile((socket) => send(socket, { type: "done", result: { summary: "secure!" } }, "json"));
  await new Promise((resolve) => setTimeout(resolve, 50));
  await assert.rejects(inventing(VULNERABLE), (e: unknown) => e instanceof ReviewStoppedError && e.reason === "crash");
  await assert.rejects(malformed(VULNERABLE), (e: unknown) => e instanceof ReviewStoppedError && e.reason === "crash");
});
