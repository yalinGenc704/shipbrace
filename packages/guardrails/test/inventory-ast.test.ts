import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst } from "../src/analysis/inventory-ast.ts";
import { analyseTaint } from "../src/analysis/oracle.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const inv = (path: string, lines: string[]) =>
  buildInventoryFromAst(snapshotFromFiles([{ path, content: lines.join("\n") }]));

// --- the property the parser was adopted for ---------------------------------

test("code inside a string literal is not analysed as code", () => {
  // This is the shape of a code generator or a test fixture: real code holding
  // sample code as data. The text-based engine reported four high-severity
  // problems here; none of them existed.
  const i = inv("app/scripts/make-fixture.ts", [
    "const SAMPLE = [",
    '  \'app.get("/api/reports/:id", async (c) => {\',',
    '  \'  const id = c.req.param("id");\',',
    '  "  const rows = await db.query(`SELECT * FROM reports WHERE id = ${id}`);",',
    '  "});",',
    '].join("\\n");',
    "",
    "export const sample = SAMPLE;",
  ]);

  assert.deepEqual(i.doors, [], "a route inside a string is not a route");
  assert.deepEqual(i.sinks, [], "a query inside a string is not a query");
  assert.deepEqual(i.sources, [], "an input inside a string is not an input");
});

test("a template literal nested inside a string is not a query", () => {
  const i = inv("packages/scaffold/src/modules/auth.ts", [
    "const ROUTES = `",
    "  await sql\\`UPDATE refresh_sessions SET revoked_at = now() WHERE id = \\${id}\\`;",
    "`;",
  ]);
  assert.deepEqual(i.sinks.filter((s) => !s.inherentlySafe), []);
});

// --- routes ------------------------------------------------------------------

test("finds a real route with its method and path", () => {
  const i = inv("server/src/a.ts", [
    'app.get("/api/reports/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  return c.json({ id });",
    "});",
  ]);
  assert.equal(i.doors.length, 1);
  assert.equal(i.doors[0]?.method, "GET");
  assert.equal(i.doors[0]?.path, "/api/reports/:id");
  assert.equal(i.sources[0]?.binding, "id");
  assert.equal(i.sources[0]?.doorId, i.doors[0]?.id);
});

test("middleware on a prefix guards routes beneath it, and nothing else", () => {
  const i = inv("server/src/a.ts", [
    'app.use("/api/admin/*", requireUser);',
    'app.get("/api/admin/users", (c) => c.json([]));',
    'app.get("/api/public/stats", (c) => c.json([]));',
  ]);
  assert.deepEqual(i.doors.find((d) => d.path === "/api/admin/users")?.guards, ["requireUser"]);
  assert.deepEqual(i.doors.find((d) => d.path === "/api/public/stats")?.guards, []);
});

test("rate limiting is not mistaken for an access-control guard", () => {
  const i = inv("server/src/a.ts", [
    'app.use("/api/*", rateLimiter({ limit: 10 }));',
    'app.post("/api/admin/purge", (c) => c.json({}));',
  ]);
  // A rate limit slows an attacker down; it does not check who they are.
  assert.deepEqual(i.doors[0]?.guards, []);
});

// --- SQL, decided structurally ----------------------------------------------

test("an untagged SQL template is a sink; a tagged one is safe by construction", () => {
  const unsafe = inv("server/src/a.ts", [
    'app.get("/x/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  return db.query(`SELECT * FROM t WHERE id = ${id}`);",
    "});",
  ]);
  const sql = unsafe.sinks.filter((s) => s.kind === "sql");
  assert.equal(sql.length, 1);
  assert.equal(sql[0]?.inherentlySafe, false);
  assert.deepEqual(sql[0]?.operands, ["id"]);

  const safe = inv("server/src/a.ts", [
    'app.get("/x/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  return sql`SELECT * FROM t WHERE id = ${id}`;",
    "});",
  ]);
  assert.equal(safe.sinks.find((s) => s.kind === "sql")?.inherentlySafe, true);
});

test("a variable named `where` does not make a template into SQL", () => {
  // The exact false positive the text engine produced on this project's prose.
  const i = inv("packages/guardrails/src/review/modules.ts", [
    "const what = `On ${where}, ${entry} is used directly in ${operation}.`;",
  ]);
  assert.deepEqual(i.sinks, []);
});

test("a SQL template with no interpolation is not a sink", () => {
  const i = inv("server/src/a.ts", ["const q = `SELECT * FROM settings`;"]);
  assert.deepEqual(i.sinks, []);
});

// --- other sinks -------------------------------------------------------------

test("recognises shell, filesystem, html and outbound-request sinks", () => {
  const shell = inv("server/src/a.ts", ["execSync(`ping ${host}`);"]);
  assert.equal(shell.sinks[0]?.kind, "shell");
  assert.deepEqual(shell.sinks[0]?.operands, ["host"]);

  const fs = inv("server/src/a.ts", ["readFileSync(userPath);"]);
  assert.equal(fs.sinks[0]?.kind, "filesystem");

  const html = inv("app/src/P.tsx", ["export const P = () => <div dangerouslySetInnerHTML={{ __html: bio }} />;"]);
  assert.equal(html.sinks[0]?.kind, "html");
  assert.ok(html.sinks[0]?.operands.includes("bio"));

  const out = inv("server/src/a.ts", ["await fetch(target);"]);
  assert.equal(out.sinks[0]?.kind, "outbound-request");
});

test("a hardcoded URL is not an outbound-request sink", () => {
  const i = inv("server/src/a.ts", ['await fetch("https://example.com/fixed");']);
  assert.deepEqual(i.sinks, []);
});

// --- end to end through the oracle -------------------------------------------

test("the oracle still finds the real bug and clears the validated one", () => {
  const vulnerable = analyseTaint(inv("server/src/a.ts", [
    'app.get("/x/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  return db.query(`SELECT * FROM t WHERE id = ${id}`);",
    "});",
  ]));
  assert.equal(vulnerable.filter((p) => p.verdict === "exploitable").length, 1);

  const validated = analyseTaint(inv("server/src/a.ts", [
    'app.get("/x/:id", async (c) => {',
    '  const raw = c.req.param("id");',
    "  const id = Number(raw);",
    "  return db.query(`SELECT * FROM t WHERE id = ${id}`);",
    "});",
  ]));
  assert.deepEqual(validated.filter((p) => p.verdict === "exploitable"), []);
});

test("passing arguments as an array is not a shell risk; building a string is", () => {
  // The analyser reported its own `spawnSync("git", [...])` as "built by pasting
  // values into text" when nothing was being pasted. Warning on the correct
  // pattern is how a tool teaches people to ignore it.
  const safe = inv("server/src/a.ts", ['spawnSync("git", ["ls-files"], { shell: false });']);
  assert.deepEqual(safe.sinks, []);

  const fixed = inv("server/src/a.ts", ['execSync("git status");']);
  assert.deepEqual(fixed.sinks, [], "a constant command cannot be steered");

  for (const built of ["execSync(`ping ${host}`);", 'execSync("ping " + host);']) {
    assert.equal(inv("server/src/a.ts", [built]).sinks[0]?.kind, "shell", built);
  }

  // `shell: true` re-introduces a shell even with separate arguments.
  assert.equal(inv("server/src/a.ts", ["spawn(cmd, args, { shell: true });"]).sinks[0]?.kind, "shell");
});

test("a file that does not parse is skipped, not guessed at", () => {
  const i = inv("server/src/broken.ts", ["app.get('/x', (c) => { return c.json({"]);
  assert.deepEqual(i.doors, []);
});
