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

// --- following a value as far as it goes ------------------------------------

const files = (entries: Record<string, string[]>) =>
  buildInventoryFromAst(
    snapshotFromFiles(Object.entries(entries).map(([path, lines]) => ({ path, content: lines.join("\n") }))),
  );

const THREE_HOPS = {
  "server/src/repo.ts": [
    "export function runQuery(text) {",
    "  return pool.unsafe(`SELECT * FROM docs WHERE title = '${text}'`);",
    "}",
  ],
  "server/src/search.ts": [
    'import { runQuery } from "./repo.ts";',
    "export function searchTitles(term) {",
    "  const cleaned = term.trim();",
    "  return runQuery(cleaned);",
    "}",
  ],
  "server/src/service.ts": [
    'import { searchTitles } from "./search.ts";',
    "export function handleSearch(q) {",
    "  return searchTitles(q);",
    "}",
  ],
  "server/src/index.ts": [
    'import { handleSearch } from "./service.ts";',
    'app.get("/api/search", async (c) => {',
    '  const q = c.req.query("q");',
    "  return c.json(await handleSearch(q));",
    "});",
  ],
};

test("a value is followed through three functions in three files", () => {
  const result = verifyClaim({ door: "/api/search", parameter: "q", sink: "sql" }, files(THREE_HOPS));
  assert.equal(result.verdict, "valid", result.reason);
});

test("a check two functions deep still blocks the claim", () => {
  const inventory = files({
    ...THREE_HOPS,
    "server/src/search.ts": [
      'import { runQuery } from "./repo.ts";',
      "export function searchTitles(term) {",
      "  const cleaned = Number(term);",
      "  return runQuery(cleaned);",
      "}",
    ],
  });
  const result = verifyClaim({ door: "/api/search", parameter: "q", sink: "sql" }, inventory);
  assert.equal(result.verdict, "blocked", result.reason);
});

test("a helper shared by a safe and an unsafe route is judged per route", () => {
  const inventory = files({
    "server/src/index.ts": [
      "function lookup(key) {",
      "  return db.query(`SELECT * FROM items WHERE id = ${key}`);",
      "}",
      'app.get("/api/safe/:id", async (c) => {',
      '  const raw = c.req.param("id");',
      "  const id = Number(raw);",
      "  return c.json(await lookup(id));",
      "});",
      'app.get("/api/unsafe/:id", async (c) => {',
      '  const id = c.req.param("id");',
      "  return c.json(await lookup(id));",
      "});",
    ],
  });
  assert.equal(verifyClaim({ door: "/api/safe/:id", parameter: "id", sink: "sql" }, inventory).verdict, "blocked");
  assert.equal(verifyClaim({ door: "/api/unsafe/:id", parameter: "id", sink: "sql" }, inventory).verdict, "valid");
});

test("a value handed to code that was not reviewed is undecidable, not safe", () => {
  const inventory = files({
    "server/src/index.ts": [
      'import { renderReport } from "some-package";',
      'app.get("/api/reports", async (c) => {',
      '  const name = c.req.query("name");',
      "  const table = settings.reportsTable;",
      "  await db.query(`SELECT * FROM ${table}`);",
      "  return c.json(await renderReport(name));",
      "});",
    ],
  });
  const result = verifyClaim({ door: "/api/reports", parameter: "name", sink: "sql" }, inventory);
  assert.equal(result.verdict, "undecidable", result.reason);
  assert.match(result.reason, /renderReport/);
});

test("a helper name defined twice is undecidable rather than guessed", () => {
  const inventory = files({
    "server/src/a.ts": ["export function load(v) {", "  return db.query(`SELECT * FROM a WHERE id = ${v}`);", "}"],
    "server/src/b.ts": ["export function load(v) {", "  return 1;", "}"],
    "server/src/index.ts": [
      'app.get("/api/x", async (c) => {',
      '  const v = c.req.query("v");',
      "  return c.json(await load(v));",
      "});",
    ],
  });
  const result = verifyClaim({ door: "/api/x", parameter: "v", sink: "sql" }, inventory);
  assert.equal(result.verdict, "undecidable", result.reason);
});

test("with no model at all, the review proves a path through a helper", async () => {
  const { runSecurityReview } = await import("../src/review/pipeline.ts");
  const review = await runSecurityReview(
    snapshotFromFiles([
      {
        path: "server/src/index.ts",
        content: [
          "function findProject(slug) {",
          "  return db.query(`SELECT * FROM projects WHERE slug = '${slug}'`);",
          "}",
          'app.get("/api/projects/:slug", async (c) => {',
          '  const slug = c.req.param("slug");',
          "  return c.json(await findProject(slug));",
          "});",
        ].join("\n"),
      },
    ]),
  );
  const item = review.modules
    .find((m) => m.id === "injection")
    ?.items.find((i) => i.id === "injection/database");

  assert.equal(item?.risks.length, 1);
  assert.equal(item?.risks[0]?.confirmedBy, "oracle");
  assert.equal(review.stats.pairedConfirmed, 1);
  assert.equal(review.stats.proposalsMade, 0, "no model was involved");
});

// --- one user reaching another's records ----------------------------------------

const SIGNED_IN = ['app.use("/api/*", requireUser);'];

test("an ownership claim holds when nothing asks who is signed in", async () => {
  const { verifyOwnership } = await import("../src/analysis/verify.ts");
  const inventory = inv([
    ...SIGNED_IN,
    'app.get("/api/invoices/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  return c.json(await sql`SELECT * FROM invoices WHERE id = ${id}`);",
    "});",
  ]);
  const result = verifyOwnership({ door: "/api/invoices/:id", parameter: "id" }, inventory);
  assert.equal(result.verdict, "valid", result.reason);
});

test("asking who is signed in blocks an ownership claim", async () => {
  const { verifyOwnership } = await import("../src/analysis/verify.ts");
  for (const ask of ['c.get("userId")', "c.var.user", "await getSession(c)"]) {
    const inventory = inv([
      ...SIGNED_IN,
      'app.get("/api/invoices/:id", async (c) => {',
      '  const id = c.req.param("id");',
      `  const me = ${ask};`,
      "  return c.json(await sql`SELECT * FROM invoices WHERE id = ${id} AND owner = ${me}`);",
      "});",
    ]);
    const result = verifyOwnership({ door: "/api/invoices/:id", parameter: "id" }, inventory);
    assert.equal(result.verdict, "blocked", `${ask}: ${result.reason}`);
  }
});

test("an unrelated cache lookup is not mistaken for asking who is signed in", async () => {
  const { verifyOwnership } = await import("../src/analysis/verify.ts");
  const inventory = inv([
    ...SIGNED_IN,
    'app.get("/api/invoices/:id", async (c) => {',
    '  const id = c.req.param("id");',
    '  const hit = cache.get("user");',
    "  return c.json(hit ?? await sql`SELECT * FROM invoices WHERE id = ${id}`);",
    "});",
  ]);
  const result = verifyOwnership({ door: "/api/invoices/:id", parameter: "id" }, inventory);
  assert.equal(result.verdict, "valid", result.reason);
});

test("an ownership claim on a route with no sign-in is not this problem", async () => {
  const { verifyOwnership } = await import("../src/analysis/verify.ts");
  const result = verifyOwnership({ door: "/api/reports/:id", parameter: "id" }, inv(VULNERABLE));
  assert.equal(result.verdict, "no-path");
  assert.match(result.reason, /does not require signing in/);
});

test("a confirmed ownership gap lands on the checklist as a high risk", async () => {
  const { runSecurityReview } = await import("../src/review/pipeline.ts");
  const review = await runSecurityReview(
    snapshotFromFiles([{
      path: "server/src/index.ts",
      content: [
        ...SIGNED_IN,
        'app.get("/api/invoices/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  return c.json(await sql`SELECT * FROM invoices WHERE id = ${id}`);",
        "});",
      ].join("\n"),
    }]),
    {
      proposer: {
        name: "scripted",
        propose: () =>
          Promise.resolve([
            { door: "/api/invoices/:id", parameter: "id", payload: "", expectedSink: "ownership", rationale: "invoices are per customer" },
          ]),
      },
    },
  );
  const item = review.modules
    .find((m) => m.id === "access-control")
    ?.items.find((i) => i.id === "access-control/object-ownership");
  assert.equal(item?.status, "action-needed");
  assert.equal(item?.risks[0]?.grade, "high");
  assert.match(item?.risks[0]?.what ?? "", /never checks that the record belongs/);
});

test("a route registered twice at the same place does not loop forever", () => {
  const inventory = inv([
    'app.get("/api/x", (c) => c.text("a"));',
    'app.get("/api/x", (c) => c.text("b"));',
  ]);
  const result = verifyClaim({ door: "/api/x", parameter: "q", sink: "sql" }, inventory);
  assert.ok(["not-found", "no-path"].includes(result.verdict));
});
