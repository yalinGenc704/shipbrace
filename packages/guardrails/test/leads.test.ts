import assert from "node:assert/strict";
import { test } from "node:test";
import { scan } from "../src/engine.ts";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const ids = (content: string, path = "server/src/a.ts") =>
  scan(snapshotFromFiles([{ path, content }])).findings.map((f) => f.ruleId);

test("a visitor's text sent to a model whose answer runs a query is a lead", () => {
  const route = (use: string) => [
    'app.post("/ask", async (c) => {',
    "  const { question } = await c.req.json();",
    '  const reply = await anthropic.messages.create({ model: "m", max_tokens: 500, messages: [{ role: "user", content: question }] });',
    "  const sqlText = reply.content[0].text;",
    `  ${use}`,
    "});",
  ].join("\n");
  assert.ok(ids(route("const rows = await db.query(sqlText); return c.json(rows);")).includes("ai/prompt-to-action"));
  assert.deepEqual(ids(route("return c.json({ answer: sqlText });")).filter((r) => r === "ai/prompt-to-action"), []);
});

test("a model given tools with a visitor's text is a lead; one with no visitor input is not", () => {
  const withTools = [
    'app.post("/agent", async (req, res) => {',
    "  const result = await openai.chat.completions.create({ model: 'm', messages: [{ role: 'user', content: req.body.text }], tools });",
    "  res.json(result);",
    "});",
  ].join("\n");
  assert.ok(ids(withTools).includes("ai/prompt-to-action"));
  const fixed = "export async function summary() { const r = await anthropic.messages.create({ messages: [{ role: 'user', content: 'hi' }] }); await db.query(r.text); }";
  assert.deepEqual(ids(fixed).filter((r) => r === "ai/prompt-to-action"), []);
});

test("a route sending every row back is a lead; filtered or limited reads are not", () => {
  const unbounded = (code: string) => ids(code, "server/routes.js").filter((r) => r === "design/unbounded-list").length;
  assert.equal(unbounded('app.get("/posts", async (req, res) => { res.json(await Post.find()); });'), 1);
  assert.equal(unbounded('app.get("/posts", async (req, res) => { const all = await prisma.post.findMany(); res.json(all); });'), 1);
  assert.equal(unbounded('app.get("/o", async (c) => { const r = await db.prepare("SELECT * FROM orders").all(); return c.json(r); });'), 1);
  assert.equal(unbounded('app.get("/posts", async (req, res) => { res.json(await prisma.post.findMany({ take: 50 })); });'), 0);
  assert.equal(unbounded('app.get("/o", async (c) => { const r = await db.prepare("SELECT * FROM orders WHERE user_id = ?").bind(u).all(); return c.json(r); });'), 0);
  assert.equal(unbounded('app.get("/x", async (req, res) => { const hit = items.find(); res.json(hit); });'), 0);
});

test("both lead rules are leads, never risks", async () => {
  const review = await runSecurityReview(snapshotFromFiles([
    { path: "server/routes.js", content: 'app.get("/posts", async (req, res) => { res.json(await Post.find()); });' },
  ]));
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === "design/unbounded-lists")!;
  assert.equal(item.risks.length, 0);
  assert.equal(item.unproven.length, 1);
  assert.equal(item.status, "needs-your-review");
});

test("the reviewer's AI shapes: plain generateText, Next.js requests, safe uses of the answer", () => {
  const ai = (code: string) => ids(code, "app/api/ask/route.ts").filter((r) => r === "ai/prompt-to-action").length;
  assert.equal(ai("export async function POST(request) { const { q } = await request.json(); const r = await generateText({ model, tools, prompt: q }); return Response.json(r); }"), 1);
  const asked = (use: string) =>
    ids(`app.post("/ask", async (req, res) => { const reply = await openai.chat.completions.create({ messages: [{ role: "user", content: req.body.q }] }); const text = reply.choices[0].message.content; ${use} });`, "server/a.js")
      .filter((r) => r === "ai/prompt-to-action").length;
  assert.equal(asked("res.send(text);"), 0, "showing the answer back is not acting on it");
  assert.equal(asked("await Message.create({ text });"), 0, "saving the chat log is not acting on it");
  assert.equal(asked("await db.query(text);"), 1);
  assert.equal(ids('app.post("/x", async (req, res) => { const out = await lambdaClient.invoke({ Payload: req.body }); await db.query(out); }); // openai', "server/a.js")
    .filter((r) => r === "ai/prompt-to-action").length, 0);
});

test("whole-table lists: template SQL counts, admin routes do not", () => {
  const unbounded = (code: string) => ids(code, "server/routes.js").filter((r) => r === "design/unbounded-list").length;
  assert.equal(unbounded("app.get('/p', async (req, res) => { const r = await pool.query(`SELECT * FROM posts`); res.json(r.rows); });"), 1);
  assert.equal(unbounded("app.get('/users', requireAdmin, async (req, res) => { res.json(await User.findAll()); });"), 0);
});

test("with no sign of AI at all the AI item says it does not apply, never that it passed", async () => {
  const review = await runSecurityReview(snapshotFromFiles([{ path: "package.json", content: JSON.stringify({ name: "x", dependencies: { hono: "4.0.0" } }) }]));
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === "injection/ai-instructions")!;
  assert.equal(item.status, "does-not-apply");
  assert.ok(item.notApplicable);
});

test("an AI service called directly, without a known library, goes back to the user", async () => {
  const review = await runSecurityReview(snapshotFromFiles([
    { path: "package.json", content: JSON.stringify({ name: "x", dependencies: { hono: "4.0.0" } }) },
    { path: "src/chat.ts", content: 'export const ask = (q: string) => fetch("https://api.openai.com/v1/chat/completions", { method: "POST", body: q });' },
  ]));
  const item = review.modules.flatMap((m) => m.items).find((i) => i.id === "injection/ai-instructions")!;
  assert.equal(item.status, "needs-your-review");
});
