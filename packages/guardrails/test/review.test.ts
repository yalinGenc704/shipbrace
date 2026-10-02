import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventory, findDoors } from "../src/analysis/inventory.ts";
import { analyseTaint, confirmAll, confirmProposal } from "../src/analysis/oracle.ts";
import type { AttackProposal } from "../src/analysis/oracle.ts";
import { parseProposals } from "../src/analysis/proposer.ts";
import { buildReview, moduleSkeleton } from "../src/review/modules.ts";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const snap = (path: string, content: string) => snapshotFromFiles([{ path, content }]);

const VULNERABLE = [
  'import { Hono } from "hono";',
  "const app = new Hono();",
  "",
  'app.get("/api/reports/:id", async (c) => {',
  '  const id = c.req.param("id");',
  "  const rows = await db.query(`SELECT * FROM reports WHERE id = ${id}`);",
  "  return c.json(rows);",
  "});",
].join("\n");

const VALIDATED = [
  'import { Hono } from "hono";',
  "const app = new Hono();",
  "",
  'app.get("/api/reports/:id", async (c) => {',
  '  const raw = c.req.param("id");',
  "  const id = Number(raw);",
  "  const rows = await db.query(`SELECT * FROM reports WHERE id = ${id}`);",
  "  return c.json(rows);",
  "});",
].join("\n");

// --- Phase 1: identification -------------------------------------------------

test("finds doors with method and path", () => {
  const doors = findDoors({ path: "server/src/a.ts", content: VULNERABLE });
  assert.equal(doors.length, 1);
  assert.equal(doors[0]?.method, "GET");
  assert.equal(doors[0]?.path, "/api/reports/:id");
});

test("detects middleware guarding a route prefix", () => {
  const doors = findDoors({
    path: "server/src/a.ts",
    content: [
      'app.use("/api/admin/*", requireUser);',
      'app.get("/api/admin/users", (c) => c.json([]));',
      'app.get("/api/public/stats", (c) => c.json([]));',
    ].join("\n"),
  });
  assert.deepEqual(doors.find((d) => d.path === "/api/admin/users")?.guards, ["requireUser"]);
  assert.deepEqual(doors.find((d) => d.path === "/api/public/stats")?.guards, []);
});

test("inventories sources and sinks inside the right door", () => {
  const inv = buildInventory(snap("server/src/a.ts", VULNERABLE));
  assert.equal(inv.sources.length, 1);
  assert.equal(inv.sources[0]?.kind, "route-param");
  assert.equal(inv.sources[0]?.binding, "id");
  assert.equal(inv.sinks.find((s) => s.kind === "sql")?.doorId, inv.doors[0]?.id);
});

// --- Phase 3: the oracle -----------------------------------------------------

test("oracle confirms an unvalidated path as exploitable", () => {
  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", VULNERABLE)));
  const sql = paths.filter((p) => p.sink.kind === "sql");
  assert.equal(sql.length, 1);
  assert.equal(sql[0]?.verdict, "exploitable");
  assert.ok(sql[0]?.via.includes("id"));
});

test("oracle clears the same path once validation intervenes", () => {
  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", VALIDATED)));
  const exploitable = paths.filter((p) => p.sink.kind === "sql" && p.verdict === "exploitable");
  assert.deepEqual(exploitable, [], "validated path should not be exploitable");
});

test("validation running AFTER the sink does not count", () => {
  const late = [
    'app.get("/api/x/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  const rows = await db.query(`SELECT * FROM t WHERE id = ${id}`);",
    "  const checked = Number(id);",
    "  return c.json({ rows, checked });",
    "});",
  ].join("\n");

  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", late)));
  assert.equal(paths.find((p) => p.sink.kind === "sql")?.verdict, "exploitable");
});

test("a tagged sql template is safe by construction and yields no path", () => {
  const safe = [
    'app.get("/api/x/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  const rows = await sql`SELECT * FROM t WHERE id = ${id}`;",
    "  return c.json(rows);",
    "});",
  ].join("\n");

  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", safe)));
  assert.deepEqual(paths.filter((p) => p.verdict === "exploitable"), []);
});

test("taint follows a value through an intermediate assignment", () => {
  const aliased = [
    'app.post("/api/run", async (c) => {',
    "  const body = await c.req.json();",
    "  const target = body;",
    "  execSync(`ping ${target}`);",
    "});",
  ].join("\n");

  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", aliased)));
  assert.ok(
    paths.some((p) => p.sink.kind === "shell" && p.verdict === "exploitable"),
    "alias should stay tainted",
  );
});

// --- The LLM boundary --------------------------------------------------------

test("a hallucinated proposal is never confirmed", () => {
  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", VALIDATED)));
  const invented: AttackProposal = {
    door: "/api/does-not-exist",
    parameter: "id",
    payload: "1 OR 1=1",
    expectedSink: "sql",
    rationale: "Invented by a model.",
  };
  assert.notEqual(confirmProposal(invented, paths).verdict, "exploitable");
});

test("a grounded proposal is confirmed and carries the oracle's path", () => {
  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", VULNERABLE)));
  const real: AttackProposal = {
    door: "/api/reports/:id",
    parameter: "id",
    payload: "1 OR 1=1",
    expectedSink: "sql",
    rationale: "Route parameter is interpolated into the query.",
  };
  const result = confirmProposal(real, paths);
  assert.equal(result.verdict, "exploitable");
  assert.equal(result.path?.sink.kind, "sql");
});

test("confirmAll splits proposals into confirmed and unverified", () => {
  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", VULNERABLE)));
  const { confirmed, unverified } = confirmAll(
    [
      {
        door: "/api/reports/:id",
        parameter: "id",
        payload: "x",
        expectedSink: "sql",
        rationale: "real",
      },
      {
        door: "/api/ghost",
        parameter: "q",
        payload: "x",
        expectedSink: "shell",
        rationale: "invented",
      },
    ],
    paths,
  );
  assert.equal(confirmed.length, 1);
  assert.equal(unverified.length, 1);
});

test("malformed model output yields no proposals rather than throwing", () => {
  assert.deepEqual(parseProposals("not json at all"), []);
  assert.deepEqual(parseProposals('{"proposals":"wrong type"}'), []);
  assert.deepEqual(parseProposals('{"proposals":[{"door":1}]}'), []);
});

// --- Phase 4: the ten modules ------------------------------------------------

test("exactly ten modules, in OWASP priority order", () => {
  assert.equal(moduleSkeleton.length, 10);
  assert.deepEqual(moduleSkeleton.map((m) => m.rank), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
  assert.deepEqual(
    moduleSkeleton.map((m) => m.owasp),
    ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"].map(
      (code) => `${code}:2025`,
    ),
  );
});

test("every risk carries what, impact, fix, and a grade", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VULNERABLE));
  const risks = review.modules.flatMap((m) => m.items.flatMap((i) => i.risks));
  assert.ok(risks.length > 0);

  for (const risk of risks) {
    assert.ok(risk.what.length > 20, `what too thin: ${risk.what}`);
    assert.ok(risk.impact.length > 20, `impact too thin: ${risk.impact}`);
    assert.ok(risk.fix.length > 20, `fix too thin: ${risk.fix}`);
    assert.ok(["high", "medium", "low"].includes(risk.grade));
    assert.ok(["oracle", "rule"].includes(risk.confirmedBy));
  }
});

test("risk explanations avoid security jargon", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VULNERABLE));
  const prose = review.modules
    .flatMap((m) => m.items.flatMap((i) => i.risks.map((r) => `${r.what} ${r.impact} ${r.fix}`)))
    .join(" ")
    .toLowerCase();

  for (const jargon of ["taint", "sink", "sanitiz", "cwe", "payload"]) {
    assert.ok(!prose.includes(jargon), `leaked jargon: ${jargon}`);
  }
});

test("the SQL risk lands in the injection module", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VULNERABLE));
  const injection = review.modules.find((m) => m.id === "injection");
  const item = injection?.items.find((i) => i.id === "injection/database");
  assert.equal(item?.status, "action-needed");
  assert.equal(item?.risks[0]?.grade, "high");
});

test("human-judgement items are surfaced for review, not silently passed", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VALIDATED));
  const design = review.modules.find((m) => m.id === "insecure-design");
  const manual = design?.items.filter((i) => i.detector === null) ?? [];

  assert.ok(manual.length > 0);
  for (const item of manual) {
    assert.equal(item.status, "needs-your-review");
    assert.ok((item.question?.length ?? 0) > 30);
  }
  assert.ok(review.summary.awaitingReview > 0);
});

test("unverified proposals are never counted as risks", () => {
  const review = buildReview({
    findings: [],
    paths: [],
    inventory: { doors: [], sources: [], sinks: [], sanitizers: [], assignments: [] },
    unverified: [
      {
        proposal: {
          door: "/x",
          parameter: "q",
          payload: "p",
          expectedSink: "sql",
          rationale: "a hunch",
        },
        verdict: "indeterminate",
      },
    ],
  });

  assert.equal(review.summary.high + review.summary.medium + review.summary.low, 0);
  assert.equal(review.unverified.length, 1);
  assert.ok((review.unverified[0]?.whyNotShown.length ?? 0) > 20);
});

test("an unguarded write route is an access-control risk; public ones are not", async () => {
  const review = await runSecurityReview(
    snap(
      "server/src/a.ts",
      [
        'app.post("/api/admin/delete-everything", (c) => c.json({}));',
        'app.get("/api/health", (c) => c.json({ ok: true }));',
        'app.post("/api/auth/login", (c) => c.json({}));',
      ].join("\n"),
    ),
  );

  const item = review.modules
    .find((m) => m.id === "access-control")
    ?.items.find((i) => i.id === "access-control/unguarded-routes");

  assert.equal(item?.risks.length, 1);
  assert.match(item?.risks[0]?.what ?? "", /delete-everything/);
  assert.equal(item?.risks[0]?.grade, "high");
});

// --- Honesty properties ------------------------------------------------------

test("an item with no detector can never report as passed", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", "const x = 1;"));

  for (const module of review.modules) {
    for (const item of module.items) {
      if (item.detector === null) {
        assert.notEqual(
          item.status,
          "pass",
          `${item.id} claims to pass but nothing checks it`,
        );
        assert.ok((item.question?.length ?? 0) > 30, `${item.id} needs a question for the user`);
      }
    }
  }
});

test("one problem on one line is reported once, preferring the traced path", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VULNERABLE));
  const item = review.modules
    .find((m) => m.id === "injection")
    ?.items.find((i) => i.id === "injection/database");

  // The taint oracle and the pattern rule both match line 6. That is one bug.
  assert.equal(item?.risks.length, 1);
  assert.equal(item?.risks[0]?.confirmedBy, "oracle");
  assert.ok(item?.risks[0]?.evidence, "the surviving risk should carry the traced path");
});

test("a line only the pattern check flags is a lead, never a risk", async () => {
  // A fixed table name: built by pasting, but nothing a visitor sends reaches it.
  const review = await runSecurityReview(
    snap(
      "server/src/a.ts",
      [
        'app.get("/api/stats", async (c) => {',
        '  const table = "daily_stats";',
        "  return c.json(await db.query(`SELECT * FROM ${table}`));",
        "});",
      ].join("\n"),
    ),
  );
  const item = review.modules
    .find((m) => m.id === "injection")
    ?.items.find((i) => i.id === "injection/database");

  assert.equal(item?.risks.length, 0, "an unproven line must not be called a risk");
  assert.equal(item?.unproven.length, 1);
  // Not a pass either: someone still has to look.
  assert.equal(item?.status, "needs-your-review");
  assert.equal(review.summary.unproven, 1);
});

test("lead explanations avoid security jargon", async () => {
  const review = await runSecurityReview(
    snap("server/src/a.ts", "export const q = (t) => db.query(`SELECT * FROM x WHERE a = ${t}`);"),
  );
  const leads = review.modules.flatMap((m) => m.items.flatMap((i) => i.unproven));
  assert.ok(leads.length > 0);

  const prose = leads.map((l) => `${l.what} ${l.why} ${l.check}`).join(" ").toLowerCase();
  for (const jargon of ["taint", "sink", "sanitiz", "cwe", "payload"]) {
    assert.ok(!prose.includes(jargon), `leaked jargon: ${jargon}`);
  }
});

test("code sent to the model never includes .env files or unredacted keys", async () => {
  const { excerptsFor } = await import("../src/review/pipeline.ts");
  const excerpts = excerptsFor(
    snapshotFromFiles([
      { path: ".env", content: "DATABASE_URL=postgres://admin:hunter2@db/prod\nSTRIPE_KEY=sk-live1234567890abcdef" },
      { path: "server/src/index.ts", content: 'const apiKey = "sk-live1234567890abcdef";\napp.get("/x", (c) => c.text("ok"));' },
      { path: "package-lock.json", content: "{}" },
    ]),
    60_000,
  );
  assert.deepEqual(excerpts.map((e) => e.path), ["server/src/index.ts"]);
  const sent = excerpts.map((e) => e.code).join("\n");
  assert.ok(!sent.includes("sk-live1234567890abcdef"), "a key reached the model");
  assert.ok(!sent.includes("hunter2"));
});

test("a sign-in check named on the route itself counts as protection", async () => {
  const review = await runSecurityReview(
    snap(
      "server/routes/app.js",
      [
        'router.get("/admin", authHandler.isAuthenticated, (req, res) => res.send("ok"));',
        'router.post("/upload", upload.single("doc"), (req, res) => res.send("ok"));',
      ].join("\n"),
    ),
  );
  const item = review.modules
    .find((m) => m.id === "access-control")
    ?.items.find((i) => i.id === "access-control/unguarded-routes");
  // The upload handler is not a sign-in check, so that route is still open.
  assert.deepEqual(item?.risks.map((r) => r.what.split(" (")[0]), ["POST /upload"]);
});

test("a model that refuses leaves the rules' findings intact and says so", async () => {
  const { ProposerRefusedError } = await import("../src/analysis/proposer.ts");
  const review = await runSecurityReview(snap("server/src/a.ts", VULNERABLE), {
    proposer: { name: "refuses", propose: () => Promise.reject(new ProposerRefusedError("cyber")) },
  });
  assert.equal(review.stats.model.status, "refused");
  const item = review.modules
    .find((m) => m.id === "injection")
    ?.items.find((i) => i.id === "injection/database");
  assert.equal(item?.risks.length, 1, "the rules' own finding must survive the refusal");
});
