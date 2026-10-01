import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst } from "../src/analysis/inventory-ast.ts";
import { analyseTaint } from "../src/analysis/oracle.ts";
import { verifyClaim, type Claim } from "../src/analysis/verify.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const inv = (lines: string[]) =>
  buildInventoryFromAst(snapshotFromFiles([{ path: "server/src/a.ts", content: lines.join("\n") }]));

const VULNERABLE = [
  'app.get("/api/reports/:id", async (c) => {',
  '  const id = c.req.param("id");',
  "  return db.query(`SELECT * FROM reports WHERE id = ${id}`);",
  "});",
];

const VALIDATED = [
  'app.get("/api/reports/:id", async (c) => {',
  '  const raw = c.req.param("id");',
  "  const id = Number(raw);",
  "  return db.query(`SELECT * FROM reports WHERE id = ${id}`);",
  "});",
];

const claim = (over: Partial<Claim> = {}): Claim => ({
  door: "/api/reports/:id",
  parameter: "id",
  sink: "sql",
  ...over,
});

// --- the four answers --------------------------------------------------------

test("a true claim is accepted", () => {
  const result = verifyClaim(claim(), inv(VULNERABLE));
  assert.equal(result.verdict, "valid");
  assert.ok(result.via?.includes("id"));
  assert.match(result.reason, /no check in between/);
});

test("a claim about validated code is blocked, not accepted", () => {
  const result = verifyClaim(claim(), inv(VALIDATED));
  assert.equal(result.verdict, "blocked");
  assert.equal(result.blockedBy?.kind, "numeric-coercion");
});

test("a claim naming a route that does not exist is rejected", () => {
  const result = verifyClaim(claim({ door: "/api/imaginary" }), inv(VULNERABLE));
  assert.equal(result.verdict, "not-found");
  assert.match(result.reason, /No route/);
});

test("a claim naming an operation that is not there is rejected", () => {
  const result = verifyClaim(claim({ sink: "shell" }), inv(VULNERABLE));
  assert.equal(result.verdict, "not-found");
});

test("a claim naming an input that is not read is rejected", () => {
  const result = verifyClaim(claim({ parameter: "authorization header" }), inv(VULNERABLE));
  assert.equal(result.verdict, "not-found");
});

test("a parameterised query blocks the claim rather than rejecting it", () => {
  const safe = inv([
    'app.get("/api/reports/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  return sql`SELECT * FROM reports WHERE id = ${id}`;",
    "});",
  ]);
  const result = verifyClaim(claim(), safe);
  assert.equal(result.verdict, "blocked");
  assert.match(result.reason, /parameterised/);
});

// --- the capability the old design lacked ------------------------------------

test("the verifier follows a value into another function; the all-paths pass does not", () => {
  const acrossFunctions = [
    "function runLookup(value) {",
    "  return db.query(`SELECT * FROM reports WHERE id = ${value}`);",
    "}",
    "",
    'app.get("/api/reports/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  const result = runLookup(id);",
    "  return c.json(result);",
    "});",
  ];
  const inventory = inv(acrossFunctions);

  // The all-paths pass scopes to one handler, so the query in `runLookup`
  // is outside it and no path is produced.
  const allPaths = analyseTaint(inventory).filter((p) => p.verdict === "exploitable");
  assert.deepEqual(allPaths, [], "precondition: the enumerating pass misses this");

  // Verifying the specific claim does find it.
  const result = verifyClaim(claim(), inventory);
  assert.equal(result.verdict, "valid", result.reason);
});

test("a claim can be verified without naming a route", () => {
  const result = verifyClaim({ sink: "sql", parameter: "id" }, inv(VULNERABLE));
  assert.equal(result.verdict, "valid");
});

// --- the property that makes it trustworthy ----------------------------------

test("the verdict ignores how confident or detailed the claim sounds", () => {
  const inventory = inv(VALIDATED);

  const confident = verifyClaim(
    claim({ origin: "a very sure model, high confidence, CRITICAL" }),
    inventory,
  );
  const vague = verifyClaim(claim({ origin: "" }), inventory);

  // Same code, same verdict, regardless of the wrapper.
  assert.equal(confident.verdict, "blocked");
  assert.equal(vague.verdict, "blocked");
});

// --- the whole point, across files -------------------------------------------

const APP = [
  {
    path: "server/src/db.ts",
    content: [
      "export function findReportsFor(owner) {",
      "  return pool.unsafe(`SELECT * FROM reports WHERE owner = '${owner}'`);",
      "}",
      "export function countFor(owner) {",
      "  return pool.unsafe(`SELECT count(*) FROM reports WHERE owner = '${owner}'`);",
      "}",
    ].join("\n"),
  },
  {
    path: "server/src/index.ts",
    content: [
      'import { countFor, findReportsFor } from "./db.ts";',
      "const app = new Hono();",
      "",
      'app.get("/api/direct/:id", async (c) => {',
      '  const id = c.req.param("id");',
      "  return c.json(await pool.unsafe(`SELECT * FROM items WHERE id = ${id}`));",
      "});",
      "",
      'app.get("/api/reports", async (c) => {',
      '  const owner = c.req.query("owner");',
      "  return c.json(await findReportsFor(owner));",
      "});",
      "",
      'app.get("/api/count", async (c) => {',
      '  const raw = c.req.query("owner");',
      "  const owner = Number(raw);",
      "  return c.json(await countFor(owner));",
      "});",
    ].join("\n"),
  },
];

test("a claim reaches a bug the enumerating pass cannot see", () => {
  const inventory = buildInventoryFromAst(snapshotFromFiles(APP));

  // Enumerating every path scopes to a single handler, so it finds only the
  // query written inside one.
  const enumerated = analyseTaint(inventory).filter((p) => p.verdict === "exploitable");
  assert.equal(enumerated.length, 1, "precondition: only the direct bug is found unaided");

  // The same rules, asked about a specific route, follow the value into the
  // helper in another file and confirm a second, real bug.
  const crossFile = verifyClaim(
    { door: "/api/reports", parameter: "owner", sink: "sql" },
    inventory,
  );
  assert.equal(crossFile.verdict, "valid", crossFile.reason);
  assert.match(crossFile.sink?.location.path ?? "", /db\.ts$/);
});

test("validation stops the value, even when it is passed to another file", () => {
  const inventory = buildInventoryFromAst(snapshotFromFiles(APP));
  const result = verifyClaim({ door: "/api/count", parameter: "owner", sink: "sql" }, inventory);

  // `Number(raw)` means what travels onward is no longer the visitor's value.
  // Reporting this route would be a warning about already-correct code.
  assert.notEqual(result.verdict, "valid", result.reason);
});

test("taint does not leak between functions that share a parameter name", () => {
  // `findReportsFor` and `countFor` both name their parameter `owner`. Matching
  // on names alone attributed the validated route's value to the wrong helper.
  const inventory = buildInventoryFromAst(snapshotFromFiles(APP));
  const result = verifyClaim({ door: "/api/count", parameter: "owner", sink: "sql" }, inventory);

  assert.notEqual(result.sink?.location.line, 2, "matched the wrong helper's query");
});

test("every rejection says which step failed", () => {
  const inventory = inv(VULNERABLE);
  for (const c of [
    claim({ door: "/nope" }),
    claim({ sink: "shell" }),
    claim({ parameter: "cookie" }),
  ]) {
    const result = verifyClaim(c, inventory);
    assert.notEqual(result.verdict, "valid");
    assert.ok(result.reason.length > 15, `thin reason: ${result.reason}`);
  }
});
