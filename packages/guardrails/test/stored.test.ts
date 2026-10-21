import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst } from "../src/analysis/inventory-ast.ts";
import { analyseTaint } from "../src/analysis/oracle.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const HEAD = ['import { Hono } from "hono";', "const app = new Hono();"];
const stored = (files: Array<{ path: string; content: string[] }>) =>
  buildInventoryFromAst(snapshotFromFiles(files.map((f) => ({ path: f.path, content: f.content.join("\n") }))))
    .sources.filter((s) => s.kind === "stored-data");

const SHOW = [
  'app.get("/notes", async (c) => {',
  '  const { results } = await c.env.DB.prepare("SELECT body FROM notes").all();',
  '  return c.html(`<p>${results.map((r) => r.body).join("")}</p>`);',
  "});",
];

test("a table written with a visitor's value is an input where it is read, across files", () => {
  const sources = stored([
    { path: "server/src/save.ts", content: [...HEAD, 'app.post("/notes", async (c) => {', "  const { body } = await c.req.json();", '  await c.env.DB.prepare("INSERT INTO notes (body) VALUES (?)").bind(body).run();', "});"] },
    { path: "server/src/show.ts", content: [...HEAD, ...SHOW] },
  ]);
  assert.equal(sources.length, 1);
  assert.equal(sources[0]?.binding, "results");
  const inventory = buildInventoryFromAst(snapshotFromFiles([
    { path: "server/src/save.ts", content: [...HEAD, 'app.post("/notes", async (c) => {', "  const { body } = await c.req.json();", '  await c.env.DB.prepare("INSERT INTO notes (body) VALUES (?)").bind(body).run();', "});"].join("\n") },
    { path: "server/src/show.ts", content: [...HEAD, ...SHOW].join("\n") },
  ]));
  assert.ok(analyseTaint(inventory).some((p) => p.source.kind === "stored-data" && p.sink.kind === "html" && p.verdict === "exploitable"));
});

test("a table nobody writes from a visitor's input stays trusted", () => {
  assert.deepEqual(stored([{ path: "server/src/show.ts", content: [...HEAD, ...SHOW] }]), []);
});

test("a value checked before it is saved does not make the table an input", () => {
  assert.deepEqual(
    stored([{ path: "server/src/a.ts", content: [...HEAD, 'app.post("/notes", async (c) => {', "  const raw = await c.req.json();", "  const body = Number(raw.body);", '  await c.env.DB.prepare("INSERT INTO notes (body) VALUES (?)").bind(body).run();', "});", ...SHOW] }]),
    [],
  );
});

test("a model saved straight from the request body makes its reads inputs", () => {
  const sources = stored([{ path: "server/routes.js", content: [
    'app.post("/posts", async (req, res) => { await Post.create(req.body); res.end(); });',
    'app.get("/posts", async (req, res) => { const posts = await Post.find(); res.json(posts); });',
  ] }]);
  assert.equal(sources.length, 1);
  assert.equal(sources[0]?.binding, "posts");
});

test("prose that mentions INSERT INTO is not a statement", () => {
  assert.deepEqual(
    stored([{ path: "server/src/a.ts", content: [...HEAD, 'const help = "Run INSERT INTO notes to add one";', 'app.post("/x", async (c) => { const v = await c.req.json(); console.log(help, v); });', ...SHOW] }]),
    [],
  );
});

test("counting rows does not read anything a visitor wrote", () => {
  assert.deepEqual(
    stored([{ path: "server/src/a.ts", content: [...HEAD, 'app.post("/notes", async (c) => {', "  const { body } = await c.req.json();", '  await c.env.DB.prepare("INSERT INTO notes (body) VALUES (?)").bind(body).run();', "});", 'app.get("/count", async (c) => {', '  const row = await c.env.DB.prepare("SELECT COUNT(*) AS n FROM notes").first();', "  return c.html(`<p>${row.n}</p>`);", "});"] }]),
    [],
  );
});

test("a visitor's value that only picks the row is not saved text", () => {
  assert.deepEqual(
    stored([{ path: "server/src/a.ts", content: [...HEAD, 'app.post("/notes/:id/view", async (c) => {', '  await c.env.DB.prepare("UPDATE notes SET views = views + 1 WHERE id = ?").bind(c.req.param("id")).run();', "});", ...SHOW] }]),
    [],
  );
  assert.deepEqual(
    stored([{ path: "server/routes.js", content: [
      'app.post("/p/:id", async (req, res) => { await prisma.note.update({ where: { id: req.params.id }, data: { read: true } }); res.end(); });',
      'app.get("/p", async (req, res) => { const notes = await prisma.note.findMany(); res.json(notes); });',
    ] }]),
    [],
  );
});

test("Prisma's data is saved text, column by column", () => {
  const sources = stored([{ path: "server/routes.js", content: [
    'app.post("/p", async (req, res) => { await prisma.note.create({ data: { body: req.body.body } }); res.end(); });',
    'app.get("/p", async (req, res) => { const notes = await prisma.note.findMany(); res.json(notes); });',
  ] }]);
  assert.equal(sources.length, 1);
});

test("a read that also returns columns only the app writes stays silent", () => {
  assert.deepEqual(
    stored([{ path: "server/src/a.ts", content: [...HEAD, 'app.post("/likes", async (c) => {', "  const { postId } = await c.req.json();", '  await c.env.DB.prepare("INSERT INTO likes (post_ref, label) VALUES (?, \'liked\')").bind(postId).run();', "});", 'app.get("/likes", async (c) => {', '  const { results } = await c.env.DB.prepare("SELECT post_ref, label FROM likes").all();', "  return c.html(`<p>${results.map((r) => r.label).join(\"\")}</p>`);", "});"] }]),
    [],
  );
});
