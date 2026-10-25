import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst as buildInventory } from "../src/analysis/inventory-ast.ts";
import { scan } from "../src/engine.ts";
import { runProjectChecks } from "../src/review/checks.ts";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

/**
 * Text about code is not code. Running ShipBrace on itself (2026-10-25) gave
 * eleven false alarms. Most came from reading its own advice ("Replace
 * `origin: true` ..."), its benchmark apps kept as text, and a test holding a
 * Supabase example as if the app did those things; the row-lock ones also
 * came from judging a Cloudflare D1 database by Supabase's rules.
 */

type File = { path: string; content: string };

const status = (files: File[], item: string) => {
  const snapshot = snapshotFromFiles(files);
  return runProjectChecks(snapshot, buildInventory(snapshot)).get(item);
};
const ruleIds = (path: string, content: string) =>
  scan(snapshotFromFiles([{ path, content }])).findings.map((f) => f.ruleId);
/** The project checks' risk ids for one file. */
const projectRiskIds = (path: string, content: string) => {
  const snapshot = snapshotFromFiles([{ path, content }]);
  return [...runProjectChecks(snapshot, buildInventory(snapshot)).values()]
    .flatMap((o) => (o.status === "risks" ? o.risks.map((r) => r.id.split("@")[0]!) : []));
};

// --- Supabase -----------------------------------------------------------------

const D1_MIGRATION: File = { path: "cloud/migrations/0001_reviews.sql", content: "CREATE TABLE reviews (id TEXT PRIMARY KEY);" };

test("a Supabase example inside a test does not make the project a Supabase app", () => {
  const testFile: File = {
    path: "packages/checker/test/wording.test.ts",
    content: `const sample = 'import { createBrowserClient } from "@supabase/ssr";';`,
  };
  assert.equal(status([D1_MIGRATION, testFile], "access-control/database-rules")?.status, "not-applicable");
});

test("a Supabase example kept as text in the app's own code does not count either", () => {
  const generator: File = {
    path: "src/templates.ts",
    content: "export const page = `import { createClient } from \"@supabase/supabase-js\";\nexport const db = createClient(u, k);`;",
  };
  assert.equal(status([D1_MIGRATION, generator], "access-control/database-rules")?.status, "not-applicable");
});

test("with a supabase folder, only its SQL can raise an alarm; other tables go back to the user", () => {
  const files = (supabaseSql: string): File[] => [
    { path: "supabase/migrations/1.sql", content: supabaseSql },
    D1_MIGRATION,
  ];
  // The D1 tables are not called a risk; they go back to the user, named,
  // since the files cannot say whether they are the same database.
  const secured = status(files("create table public.notes (id int);\nalter table public.notes enable row level security;"), "access-control/database-rules");
  assert.equal(secured?.status, "not-applicable");
  assert.ok(secured?.status === "not-applicable" && secured.reason.includes("cloud/migrations/0001_reviews.sql") && !secured.absent);
  // A real Supabase table without row rules is still reported.
  const open = status(files("create table public.notes (id int);"), "access-control/database-rules");
  assert.equal(open?.status, "risks");
  assert.ok(open?.status === "risks" && open.risks.every((r) => r.location?.path.startsWith("supabase/")));
});

test("a test file is not app code, even when it really imports Supabase", () => {
  const testFile: File = { path: "test/db.test.ts", content: 'import { createClient } from "@supabase/supabase-js";\ncreateClient(u, k);' };
  assert.equal(status([D1_MIGRATION, testFile], "access-control/database-rules")?.status, "not-applicable");
});

test("a supabase folder holding only seed data does not hide tables made elsewhere", () => {
  const files: File[] = [
    { path: "package.json", content: JSON.stringify({ name: "app", dependencies: { "@supabase/supabase-js": "2.0.0" } }) },
    { path: "supabase/seed.sql", content: "insert into notes (id) values (1);" },
    { path: "drizzle/0000_init.sql", content: 'CREATE TABLE "notes" ("id" integer);' },
  ];
  assert.equal(status(files, "access-control/database-rules")?.status, "risks");
});

test("Supabase tables locked, but another tool's tables open, never passes", () => {
  const files: File[] = [
    { path: "supabase/migrations/1.sql", content: "create table public.profiles (id uuid);\nalter table public.profiles enable row level security;" },
    { path: "drizzle/0000_init.sql", content: 'CREATE TABLE "notes" ("id" integer);' },
  ];
  assert.equal(status(files, "access-control/database-rules")?.status, "not-applicable");
  // Locked in the other tool's SQL as well: nothing left to ask.
  files.push({ path: "drizzle/0001_rls.sql", content: 'ALTER TABLE "notes" ENABLE ROW LEVEL SECURITY;' });
  assert.equal(status(files, "access-control/database-rules")?.status, "pass");
});

test("a Supabase import in real code still makes it a Supabase app", () => {
  const app: File = { path: "lib/db.ts", content: 'import { createClient } from "@supabase/supabase-js";\nexport const db = createClient(u, k);' };
  assert.equal(status([app, { path: "db/1.sql", content: "create table notes (id int);" }], "access-control/database-rules")?.status, "risks");
});

// --- Rules that read line by line -------------------------------------------------

test("advice that mentions origin: true is not a CORS setting; the setting itself is", () => {
  const advice = 'const detail = "Replace the CORS wildcard (`*` / `origin: true`) with a list of your sites.";';
  assert.deepEqual(ruleIds("src/rules.ts", advice).filter((id) => id === "auth/permissive-cors"), []);
  assert.deepEqual(ruleIds("src/rules.ts", "// we used to have origin: true here").filter((id) => id === "auth/permissive-cors"), []);
  assert.ok(ruleIds("server/index.ts", "app.use(cors({ origin: true, credentials: true }));").includes("auth/permissive-cors"));
  assert.ok(ruleIds("server/index.ts", 'app.use(cors({ origin: "*" }));').includes("auth/permissive-cors"));
});

test("sample code kept as text is not a token in localStorage or a default signing key", () => {
  const sample = "export const app = `\nlocalStorage.setItem('token', t);\nconst key = process.env.JWT_SECRET || 'dev secret';\n`;";
  const ids = ruleIds("bench/cases.ts", sample);
  assert.ok(!ids.includes("auth/token-in-localstorage"), ids.join());
  assert.ok(!ids.includes("auth/default-jwt-secret"), ids.join());
  // The same lines as code are still found.
  const real = ruleIds("web/auth.ts", "localStorage.setItem('token', t);\nconst key = process.env.JWT_SECRET || 'dev secret';");
  assert.ok(real.includes("auth/token-in-localstorage"));
  assert.ok(real.includes("auth/default-jwt-secret"));
});

// --- Project-wide checks --------------------------------------------------------

test("a message naming new Sequelize is not a Sequelize setup", () => {
  const message: File = {
    path: "src/checks.ts",
    content: "const fix = `Add \\`logging: false\\` to the options passed to \\`new Sequelize(...)\\` in ${path}.`;",
  };
  const risks = (files: File[]) => {
    const outcome = status(files, "logging/no-secrets");
    return outcome?.status === "risks" ? outcome.risks.map((r) => r.id.split("@")[0]) : [];
  };
  assert.ok(!risks([message]).includes("check/orm-query-logging"));
  const real: File = { path: "server/db.js", content: 'const db = new Sequelize(process.env.DATABASE_URL, { dialect: "postgres" });' };
  assert.ok(risks([real]).includes("check/orm-query-logging"));
});

test("Express apps kept as benchmark text do not make the project an Express app", () => {
  const route = 'import { Hono } from "hono";\nconst app = new Hono();\napp.get("/api/health", (c) => c.json({ ok: true }));';
  const cases: File = { path: "bench/cases.ts", content: "export const app = `\nconst app = express();\napp.get('/', h);\n`;" };
  const outcome = status([{ path: "server/index.ts", content: route }, cases], "config/error-detail");
  assert.equal(outcome?.status, "pass");
  const express: File = { path: "server/app.js", content: 'const app = express();\napp.get("/api/x", (req, res) => res.json({}));' };
  assert.equal(status([express], "config/error-detail")?.status, "not-applicable");
});

test("a protection mentioned only in text never turns into a new alarm", () => {
  // Looking for a protection still reads the whole file. Whether a mention in
  // text should hand the item back instead is a separate question.
  const server: File = {
    path: "server/index.ts",
    content: 'import { Hono } from "hono";\nconst app = new Hono();\nconst note = "we add helmet later";\napp.get("/api/x", (c) => c.json({}));',
  };
  assert.notEqual(status([server], "config/security-headers")?.status, "risks");
});

test(".js files and Windows line endings are read the same way", () => {
  for (const nl of ["\n", "\r\n"]) {
    for (const ext of ["ts", "js"]) {
      const where = `${ext} ${JSON.stringify(nl)}`;
      assert.ok(projectRiskIds(`server/app.${ext}`, "app.use(session({ secret: `keyboard cat` }));").includes("check/session-secret-in-code"), where);
      assert.ok(ruleIds(`server/auth.${ext}`, "const key = process.env.JWT_SECRET || `dev secret`;").includes("auth/default-jwt-secret"), where);
      const sample = ["export const app = `", "const x = 1;", "app.use(cors({ origin: true, credentials: true }));", "`;"].join(nl);
      assert.ok(!ruleIds(`bench/cases.${ext}`, sample).includes("auth/permissive-cors"), where);
    }
  }
});

test("a sign-in key named with a space is still found in localStorage", () => {
  assert.ok(ruleIds("web/auth.ts", "localStorage.setItem('auth token', t);").includes("auth/token-in-localstorage"));
});

test("passwords mentioned only in text hand the item back, never raise an alarm", () => {
  const text: File = { path: "src/messages.ts", content: 'export const hint = "Never store a password in plain text.";' };
  const outcome = status([text], "crypto/password-storage");
  assert.equal(outcome?.status, "not-applicable");
  assert.ok(outcome?.status === "not-applicable" && !outcome.absent);
});

// --- Queries built only from placeholders and fixed text -----------------------------

async function databaseItem(lines: string[]) {
  const review = await runSecurityReview(snapshotFromFiles([{ path: "server/src/a.ts", content: lines.join("\n") }]));
  const item = review.modules.find((m) => m.id === "injection")?.items.find((i) => i.id === "injection/database");
  return { risks: item?.risks.length ?? 0, unproven: item?.unproven.length ?? 0 };
}

const route = (body: string[]) => ['app.get("/api/x", async (c) => {', ...body, "});"];

test("one ? per item, pasted in, is not a database risk", async () => {
  assert.deepEqual(
    await databaseItem(route([
      '  const ids = c.req.queries("id") ?? [];',
      '  return c.json(await db.prepare(`SELECT * FROM t WHERE id IN (${ids.map(() => "?").join(",")})`).bind(...ids).all());',
    ])),
    { risks: 0, unproven: 0 },
  );
  // Numbered placeholders built from the index are fixed too.
  assert.deepEqual(
    await databaseItem(route([
      '  const ids = c.req.queries("id") ?? [];',
      "  return c.json(await db.query(`SELECT * FROM t WHERE id IN (${ids.map((_, i) => `$${i + 1}`).join(\", \")})`, ids));",
    ])),
    { risks: 0, unproven: 0 },
  );
  // With a fallback for an empty list.
  assert.deepEqual(
    await databaseItem(route([
      '  const ids = c.req.queries("id") ?? [];',
      '  return c.json(await db.prepare(`DELETE FROM t WHERE id IN (${ids.map(() => "?").join(",") || "NULL"})`).bind(...ids).run());',
    ])),
    { risks: 0, unproven: 0 },
  );
});

test("fixed SQL kept in a constant, or chosen between two fixed pieces, is not a database risk", async () => {
  assert.deepEqual(
    await databaseItem([
      "const LAST_DAY = \"strftime('%Y-%m-%dT%H:%M:%fZ', 'now', '-1 day')\";",
      ...route([
        '  const id = c.req.param("id");',
        "  return c.json(await db.prepare(`SELECT count(*) FROM s WHERE id = ? AND at > ${LAST_DAY}`).bind(id).first());",
      ]),
    ]),
    { risks: 0, unproven: 0 },
  );
  assert.deepEqual(
    await databaseItem(route([
      '  const ids = c.req.queries("id") ?? [];',
      '  const inList = `id IN (${ids.map(() => "?").join(",")})`;',
      '  return c.json(await db.prepare(`DELETE FROM t WHERE ${ids.length > 0 ? inList : "0"}`).bind(...ids).run());',
    ])),
    { risks: 0, unproven: 0 },
  );
});

test("anything a visitor could shape is still reported", async () => {
  // The item itself pasted in, not a ? for it.
  const pasted = await databaseItem(route([
    '  const ids = c.req.queries("id") ?? [];',
    '  return c.json(await db.prepare(`SELECT * FROM t WHERE id IN (${ids.map((id) => `\'${id}\'`).join(",")})`).all());',
  ]));
  assert.ok(pasted.risks + pasted.unproven > 0, "an item pasted in must still be reported");

  // A name declared twice cannot be trusted to be the fixed one.
  const shadowed = await databaseItem([
    'const COLUMN = "name";',
    ...route([
      '  const COLUMN = c.req.query("sort");',
      "  return c.json(await db.query(`SELECT * FROM t ORDER BY ${COLUMN}`));",
    ]),
  ]);
  assert.ok(shadowed.risks + shadowed.unproven > 0, "a shadowed constant must still be reported");

  // A `let` can change after it is set.
  const changeable = await databaseItem([
    'let column = "name";',
    ...route(["  return c.json(await db.query(`SELECT * FROM t ORDER BY ${column}`));"]),
  ]);
  assert.ok(changeable.risks + changeable.unproven > 0, "a let must still be reported");

  // A callback's index name means nothing inside a constant defined elsewhere.
  const captured = await databaseItem(route([
    '  const i = c.req.query("sort");',
    '  const ids = c.req.queries("id") ?? [];',
    "  const ORDER = `${i}`;",
    '  return c.json(await db.query(`SELECT * FROM t WHERE id IN (${ids.map((_, i) => ORDER).join(",")})`));',
  ]));
  assert.ok(captured.risks + captured.unproven > 0, "an index name must not stand in for a visitor's value");

  // lodash passes the key, not an index, as the second argument.
  const keys = await databaseItem(route([
    "  const q = c.req.query();",
    '  return c.json(await db.query(`SELECT ${_(q).map((v, k) => k).join(",")} FROM t`));',
  ]));
  assert.ok(keys.risks + keys.unproven > 0, "a wrapper's key must still be reported");

  // A constant inside another function is not the name the query uses.
  const elsewhere = await databaseItem([
    'function setup() { const COL = "name"; return COL; }',
    ...route(["  return c.json(await db.query(`SELECT * FROM t ORDER BY ${COL}`));"]),
  ]);
  assert.ok(elsewhere.risks + elsewhere.unproven > 0, "a constant out of scope must still be reported");

  // Inside `with`, a name can be a property of anything.
  const withFile = await runSecurityReview(snapshotFromFiles([{
    path: "server/src/a.cjs",
    content: ['const COL = "name";', 'app.get("/api/x", async (req, res) => {', "  with (req.query) { res.json(await db.query(`SELECT * FROM t ORDER BY ${COL}`)); }", "});"].join("\n"),
  }]));
  const withItem = withFile.modules.find((m) => m.id === "injection")?.items.find((i) => i.id === "injection/database");
  assert.ok((withItem?.risks.length ?? 0) + (withItem?.unproven.length ?? 0) > 0, "a with statement must not be trusted");

  // A visitor's value straight in is a proven risk, as before.
  const direct = await databaseItem(route([
    '  const id = c.req.param("id");',
    "  return c.json(await db.query(`SELECT * FROM t WHERE id = ${id}`));",
  ]));
  assert.ok(direct.risks > 0);
});
