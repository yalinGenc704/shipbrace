import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst as buildInventory } from "../src/analysis/inventory-ast.ts";
import { analyseTaint } from "../src/analysis/oracle.ts";
import { parseProposals } from "../src/analysis/proposer.ts";
import { buildReview, moduleSkeleton } from "../src/review/modules.ts";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";
import { leakedJargon } from "./plain-words.ts";

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
  const doors = buildInventory(snap("server/src/a.ts", VULNERABLE)).doors;
  assert.equal(doors.length, 1);
  assert.equal(doors[0]?.method, "GET");
  assert.equal(doors[0]?.path, "/api/reports/:id");
});

test("detects middleware guarding a route prefix", () => {
  const doors = buildInventory(
    snap(
      "server/src/a.ts",
      [
        'app.use("/api/admin/*", requireUser);',
        'app.get("/api/admin/users", (c) => c.json([]));',
        'app.get("/api/public/stats", (c) => c.json([]));',
      ].join("\n"),
    ),
  ).doors;
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
    assert.ok(["oracle", "rule", "route-check"].includes(risk.confirmedBy));
  }
});

test("risk explanations avoid security jargon", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VULNERABLE));
  const prose = review.modules.flatMap((m) => m.items.flatMap((i) => i.risks.flatMap((r) => [r.what, r.impact, r.fix])));
  assert.ok(prose.length > 0);
  for (const text of prose) assert.deepEqual(leakedJargon(text), [], `leaked jargon: ${text}`);
});

test("the SQL risk lands in the injection module", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VULNERABLE));
  const injection = review.modules.find((m) => m.id === "injection");
  const item = injection?.items.find((i) => i.id === "injection/database");
  assert.equal(item?.status, "action-needed");
  assert.equal(item?.risks[0]?.grade, "high");
});

test("human-judgement items are surfaced on the checklist, not silently passed", async () => {
  const review = await runSecurityReview(snap("server/src/a.ts", VALIDATED));
  const design = review.modules.find((m) => m.id === "insecure-design");
  const manual = design?.items.filter((i) => i.detector === null) ?? [];

  assert.ok(manual.length > 0);
  for (const item of manual) {
    // General questions: kept apart from "Needs your check", which is only
    // about this code, and never a pass.
    assert.equal(item.status, "checklist");
    assert.ok((item.question?.length ?? 0) > 30);
  }
  assert.ok((review.summary.checklist ?? 0) > 0);
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
        'app.post("/api/admin/delete-everything", async (c) => c.json(await deleteEverything()));',
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
  // A table name from the app's own settings: built by pasting, and no visitor
  // input can be traced to it, but the settings themselves were not reviewed.
  const review = await runSecurityReview(
    snap(
      "server/src/a.ts",
      [
        'app.get("/api/stats", async (c) => {',
        "  const table = settings.statsTable;",
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

  for (const text of leads.flatMap((l) => [l.what, l.why, l.check])) {
    assert.deepEqual(leakedJargon(text), [], `leaked jargon: ${text}`);
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
  assert.deepEqual(item?.risks.map((r) => r.what), ["The action /upload can be used by anyone, without signing in."]);
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

test("webhooks and sign-in callbacks are public by design, not open doors", async () => {
  const review = await runSecurityReview(
    snapshotFromFiles([{
      path: "server/src/index.ts",
      content: [
        'import { Hono } from "hono";',
        "const app = new Hono();",
        'app.post("/api/github/webhook", async (c) => c.json(await handle(c)));',
        'app.get("/auth/callback", async (c) => c.redirect("/"));',
        'app.post("/api/orders", async (c) => c.json(await createOrder(c)));',
      ].join("\n"),
    }]),
  );
  const open = review.modules
    .flatMap((m) => m.items)
    .find((i) => i.id === "access-control/unguarded-routes")!
    .risks.map((r) => r.what);
  assert.equal(open.length, 1);
  assert.match(open[0]!, /\/api\/orders/, "an ordinary route without sign-in is still reported");
});

test("a route that only answers with fixed text is not reported as unlocked", async () => {
  const result = await runSecurityReview(
    snap("server/src/a.ts", [
      'app.get("/gone", (c) => c.notFound());',
      'app.get("/teapot", (req, res) => res.status(418).send("No"));',
      'app.get("/echo/:id", (c) => c.text(c.req.param("id")));',
      'app.get("/stats", (c) => c.json(stats));',
    ].join("\n")),
  );
  const open = result.modules
    .flatMap((m) => m.items)
    .find((i) => i.id === "access-control/unguarded-routes")!
    .risks.map((r) => r.what);
  assert.ok(!open.some((w) => w.includes("/gone") || w.includes("/teapot")), open.join("\n"));
  assert.ok(open.some((w) => w.includes("/echo/:id")) && open.some((w) => w.includes("/stats")), open.join("\n"));
});

test("a check for one kind of danger does not clear another", () => {
  const ping = (step: string) =>
    analyseTaint(buildInventory(snap("server/src/a.ts", [
      'import { quote } from "shell-quote";',
      'app.get("/ping", (c) => {',
      '  const host = c.req.query("host");',
      `  const safe = ${step}(host);`,
      "  execSync(`ping ${safe}`);",
      "});",
    ].join("\n")))).filter((p) => p.sink.kind === "shell")[0]?.verdict;
  assert.equal(ping("escapeHtml"), "exploitable");
  assert.equal(ping("quote"), "sanitized");
  assert.equal(ping("sanitizeInput"), "sanitized", "a name that does not say which danger is credited");
});

test("a quote helper is trusted only when it says what it is for", () => {
  const verdict = (lines: string[], kind: string) =>
    analyseTaint(buildInventory(snap("server/src/a.ts", lines.join("\n")))).find((p) => p.sink.kind === kind)?.verdict;
  const route = (prelude: string[], step: string, use: string) => [
    ...prelude,
    'app.get("/x", (c) => {',
    '  const v = c.req.query("v");',
    `  const safe = ${step}(v);`,
    `  ${use}`,
    "});",
  ];
  const query = "db.query(`SELECT * FROM t WHERE name = '${safe}'`);";
  assert.equal(verdict(route([], "escapeSqlQuotes", query), "sql"), "sanitized");
  assert.equal(verdict(route([], "escapeQuotes", query), "sql"), "sanitized");
  const ping = "execSync(`ping ${safe}`);";
  assert.equal(verdict(route(['import { quote } from "shell-quote";'], "quote", ping), "shell"), "sanitized");
  assert.equal(verdict(route(["const quote = (s) => `\"${s}\"`;"], "quote", ping), "shell"), "exploitable");
});

test("echoing the request back is not answering with fixed text", () => {
  const doors = buildInventory(snap("server/routes.js", 'app.post("/echo", (req, res) => res.json(req.body));')).doors;
  assert.equal(doors[0]?.answersOnlyFixed, undefined);
});

test("a page that only sends the visitor on has nothing for a sign-in to protect", () => {
  const flag = (handler: string) => buildInventory(snap("server/routes.js", `app.get("/go", ${handler});`)).doors[0]?.onlyRedirects;
  assert.equal(flag("(req, res) => res.redirect(req.query.url)"), true);
  assert.equal(flag('function (req, res) { if (req.query.url) { res.redirect(req.query.url) } else { res.send("invalid redirect url") } }'), true);
  assert.equal(flag("(req, res) => res.redirect(302, req.params.to)"), true);
  assert.equal(flag('(c) => c.redirect(c.req.query("url"))'), true);
  assert.equal(flag('(req, res) => res.status(404).send("nowhere to go")'), undefined, "no redirect: that is answering only");

  // Anything more than that is still a page that may hold something.
  for (const more of [
    "(req, res) => { audit(req.query.url); res.redirect(req.query.url); }",
    "(req, res) => res.redirect(lookUp(req.query.id))",
    "(req, res) => res.redirect(req.session.returnTo)",
    "(req, res) => res.redirect(req.cookies.next)",
    "(req, res) => res.redirect(req.body.url)",
    "(req, res) => res.redirect(req.user.home)",
    "(req, res) => res.redirect(req.headers.referer)",
    "(req, res) => { const url = req.query.url; res.redirect(url); }",
    "(req, res) => res.redirect(target)",
    "(req, res) => res.redirect(req.query[key])",
    "(req, res, next) => { res.redirect(req.query.url); next(); }",
    '(c) => c.redirect(c.get("user").home)',
    '(c) => c.redirect(c.req.header("referer"))',
    // The request as a whole, or the answer's own copy of it, is not one field of the address.
    "(req, res) => { res.send(res.req); res.redirect(req.query.url); }",
    "(req, res) => { res.json(req.query); res.redirect(req.query.url); }",
    '(c) => { c.json(c.req); return c.redirect(c.req.query("url")); }',
    "(req, res) => res.redirect(res.locals.next)",
    // Work hidden beside the redirect.
    '(req, res) => { import("./wipe.js"); res.redirect(req.query.url); }',
    "async (req, res) => { await 0; res.redirect(req.query.url); }",
    "(req, res) => { new Job(); res.redirect(req.query.url); }",
    "(req, res) => { (() => wipe())(); res.redirect(req.query.url); }",
    "function (req, res) { this.count++; res.redirect(req.query.url); }",
  ]) {
    assert.equal(flag(more), undefined, more);
  }
  // A step before the handler does work of its own.
  assert.equal(buildInventory(snap("server/routes.js", 'app.get("/go", upload.single("f"), (req, res) => res.redirect(req.query.url));')).doors[0]?.onlyRedirects, undefined);
});

test("a redirect-only handler written in another file is found by its name", async () => {
  const routes = {
    path: "routes/app.js",
    content: [
      'const appHandler = require("../core/appHandler");',
      "module.exports = function (router) {",
      '  router.get("/redirect", appHandler.redirect);',
      '  router.get("/ping", appHandler.ping);',
      '  router.get("/both", appHandler.twice);',
      "};",
    ].join("\n"),
  };
  const handlers = {
    path: "core/appHandler.js",
    content: [
      "module.exports.redirect = function (req, res) {",
      "  if (req.query.url) { res.redirect(req.query.url) } else { res.send('invalid redirect url') }",
      "}",
      "module.exports.ping = function (req, res) { exec('ping -c 2 ' + req.body.address, function (err, stdout) { res.send(stdout) }) }",
    ].join("\n"),
  };
  const twice = { path: "core/other.js", content: "exports.twice = (req, res) => res.redirect(req.query.url);\nconst twice = (req, res) => res.send(db.all());" };
  const review = await runSecurityReview(snapshotFromFiles([routes, handlers, twice]));
  const open = review.modules.flatMap((m) => m.items).find((i) => i.id === "access-control/unguarded-routes")!.risks.map((r) => r.what);
  assert.ok(!open.some((w) => w.includes("/redirect")), "nothing to protect on /redirect");
  assert.ok(open.some((w) => w.includes("/ping")), "a page that does real work is still reported");
  assert.ok(open.some((w) => w.includes("/both")), "two functions of that name: which one runs can't be told");
  // Where it sends people is still reported, as its own problem.
  const redirects = review.modules.flatMap((m) => m.items).find((i) => i.id === "access-control/redirects")!.risks;
  assert.equal(redirects.length >= 1, true, "the open redirect itself is still found");
});

test("a handler's name is trusted only when the route's file shows where it comes from", async () => {
  const openPages = async (files: Array<{ path: string; content: string }>) =>
    (await runSecurityReview(snapshotFromFiles(files))).modules
      .flatMap((m) => m.items)
      .find((i) => i.id === "access-control/unguarded-routes")!
      .risks.map((r) => r.what);
  const harmless = { path: "lib/util.js", content: "const redirect = (req, res) => res.redirect(req.query.next);\nmodule.exports = { other: 1 };" };

  // A method on an object made here, which sends data; an unrelated function
  // of the same name elsewhere only redirects. The route is still reported.
  const method = {
    path: "server.js",
    content: [
      'const express = require("express");',
      "const app = express();",
      "class Admin { redirect(req, res) { res.json(db.allUsers()); } }",
      "const admin = new Admin();",
      'app.get("/export", admin.redirect);',
    ].join("\n"),
  };
  assert.ok((await openPages([method, harmless])).some((w) => w.includes("/export")));

  // The same name required from the wrong file, or not handed out by its file.
  const wrongFile = { path: "server.js", content: 'const app = require("express")();\nconst handlers = require("./lib/handlers");\napp.get("/go", handlers.redirect);' };
  assert.ok((await openPages([wrongFile, harmless])).some((w) => w.includes("/go")));
  const notExported = { path: "lib/handlers.js", content: "const redirect = (req, res) => res.redirect(req.query.next);\nmodule.exports = { redirect: (req, res) => res.json(db.all()) };" };
  assert.ok((await openPages([wrongFile, notExported])).some((w) => w.includes("/go")));

  // A name that means two things in the file: the local one is what the route uses.
  const shadowed = {
    path: "routes.js",
    content: [
      "function go(req, res) { res.redirect(req.query.url); }",
      "module.exports = function (router, other) {",
      "  const go = other;",
      '  router.get("/go", go);',
      "};",
    ].join("\n"),
  };
  assert.ok((await openPages([shadowed])).some((w) => w.includes("/go")));
  const parameter = {
    path: "routes.js",
    content: 'const handlers = require("./lib/handlers");\nmodule.exports = function (router, handlers) { router.get("/go", handlers.redirect); };',
  };
  assert.ok((await openPages([parameter, { path: "lib/handlers.js", content: "exports.redirect = (req, res) => res.redirect(req.query.next);" }])).some((w) => w.includes("/go")));

  // The file must hand the function out under that name, once, and not replace what it hands out.
  for (const handlers of [
    "exports.safe = function go(req, res) { res.redirect(req.query.next); };\nexports.redirect = wrap(danger);",
    "exports.redirect = (req, res) => res.redirect(req.query.next);\nmodule.exports = new Handlers();",
    "exports.redirect = (req, res) => res.redirect(req.query.next);\nexports.redirect = wrap(danger);",
  ]) {
    assert.ok((await openPages([wrongFile, { path: "lib/handlers.js", content: handlers }])).some((w) => w.includes("/go")), handlers);
  }
  // A default import is one value the file chose; its `redirect` is not the file's named function.
  const byDefault = { path: "server.ts", content: 'import express from "express";\nimport h from "./lib/h";\nconst app = express();\napp.get("/go", h.redirect);' };
  const defaultFile = { path: "lib/h.ts", content: "export const redirect = (req, res) => res.redirect(req.query.to);\nexport default new Handlers();" };
  assert.ok((await openPages([byDefault, defaultFile])).some((w) => w.includes("/go")));
  const byNamespace = { path: "server.ts", content: 'import express from "express";\nimport * as h from "./lib/h";\nconst app = express();\napp.get("/go", h.redirect);' };
  assert.ok(!(await openPages([byNamespace, defaultFile])).some((w) => w.includes("/go")));

  // Declared in the route's own file, or handed out by the file it is required from.
  const local = { path: "server.js", content: 'const app = require("express")();\nfunction go(req, res) { res.redirect(req.query.url); }\napp.get("/go", go);' };
  assert.ok(!(await openPages([local])).some((w) => w.includes("/go")));
  const exported = { path: "lib/handlers.js", content: "exports.redirect = (req, res) => res.redirect(req.query.next);" };
  assert.ok(!(await openPages([wrongFile, exported])).some((w) => w.includes("/go")));
  const named = { path: "server.ts", content: 'import express from "express";\nimport { leave } from "./lib/leave";\nconst app = express();\napp.get("/leave", leave);' };
  const namedExport = { path: "lib/leave.ts", content: "export const leave = (req, res) => res.redirect(req.query.to);" };
  assert.ok(!(await openPages([named, namedExport])).some((w) => w.includes("/leave")));
});

test("a sign-in check at the top of the handler protects the route", () => {
  const doors = buildInventory(snap("server/src/a.ts", [
    'app.post("/api/notes", async (c) => {',
    '  const user = c.get("user");',
    '  if (!user) return c.json({ error: "Sign in first" }, 401);',
    "  return c.json(await saveNote(user, await c.req.json()));",
    "});",
    'app.post("/erase", async (req, res, next) => {',
    "  const loggedInUser = security.authenticatedUsers.get(req.cookies.token);",
    "  if (!loggedInUser) { next(new Error('Blocked')); return; }",
    "  res.json(await erase(loggedInUser));",
    "});",
    'app.post("/late", async (c) => {',
    "  await deleteEverything();",
    '  const user = c.get("user");',
    "  if (!user) return c.text('no', 401);",
    "});",
    'app.post("/noexit", async (c) => {',
    '  const user = c.get("user");',
    "  if (!user) console.warn('anonymous');",
    "  return c.json(await deleteEverything());",
    "});",
  ].join("\n"))).doors;
  const guarded = (path: string) => (doors.find((d) => d.path === path)?.guards.length ?? 0) > 0;
  assert.ok(guarded("/api/notes"));
  assert.ok(guarded("/erase"));
  assert.ok(!guarded("/late"), "a check after the work does not protect it");
  assert.ok(!guarded("/noexit"), "a check that does not stop the request does not protect it");
  const lookups = buildInventory(snap("server/src/b.ts", [
    'app.get("/authors/:id", async (c) => {',
    "  const author = await getAuthor(c.req.param(\"id\"));",
    "  if (!author) return c.notFound();",
    "  return c.json(author);",
    "});",
    'app.get("/users/:id", async (c) => {',
    '  const user = await getUser(c.req.param("id"));',
    "  if (!user) return c.notFound();",
    "  return c.json(user);",
    "});",
  ].join("\n"))).doors;
  assert.deepEqual(lookups.map((d) => d.guards), [[], []], "a record that exists is not a signed-in person");
});

test("a postgres.js transaction tag is as safe as sql", () => {
  const paths = analyseTaint(buildInventory(snap("server/src/a.ts", [
    'app.post("/move/:id", async (c) => {',
    '  const id = c.req.param("id");',
    "  await sql.begin(async (tx) => {",
    "    await tx`UPDATE items SET moved = true WHERE id = ${id}`;",
    "  });",
    "});",
  ].join("\n"))));
  assert.deepEqual(paths.filter((p) => p.verdict === "exploitable"), []);
});

test("a query mentioned in documentation text is not a query", () => {
  const inventory = buildInventory(snap("server/src/readme.ts", [
    "export const readme = (name) => `# ${name}",
    "",
    "Use \\`\\` query\\`SELECT ... \\${value}\\` \\`\\` from server/src/mysql.ts.`;",
  ].join("\n")));
  assert.deepEqual(inventory.sinks.filter((s) => s.kind === "sql"), []);
});

test("a query that opens with a comment or EXPLAIN is still a query", () => {
  for (const start of ["/* list */ SELECT", "-- list\nSELECT", "EXPLAIN SELECT"]) {
    const inventory = buildInventory(snap("server/src/a.ts", `db.query(\`${start} * FROM t WHERE id = \${id}\`);`));
    assert.equal(inventory.sinks.filter((s) => s.kind === "sql").length, 1, start);
  }
});

test("XML is an operation only when outside references are switched on", () => {
  const kinds = (options: string) =>
    buildInventory(snap("server/a.js", `const doc = libxmljs.parseXmlString(xml${options});`)).sinks.map((s) => s.kind);
  assert.deepEqual(kinds(""), []);
  assert.deepEqual(kinds(", { noblanks: true }"), []);
  assert.deepEqual(kinds(", { noent: false }"), []);
  assert.deepEqual(kinds(", { noent: true }"), ["xml-entities"]);
  assert.deepEqual(kinds(", { dtdload: true }"), ["xml-entities"]);
});

test("a sign-in check inside a handler wrapped in an async function that runs at once counts", () => {
  const doors = buildInventory(snap("server/routes.ts", [
    "router.post('/', (req, res, next) => {",
    "  void (async () => {",
    "    const loggedInUser = security.authenticatedUsers.get(req.cookies.token)",
    "    if (!loggedInUser) { next(new Error('Blocked')); return }",
    "    await PrivacyRequestModel.create({ UserId: loggedInUser.data.id })",
    "  })()",
    "})",
  ].join("\n"))).doors;
  assert.ok((doors[0]?.guards.length ?? 0) > 0);
});
