import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventoryFromAst as buildInventory } from "../src/analysis/inventory-ast.ts";
import { runProjectChecks, type CheckOutcome } from "../src/review/checks.ts";
import { runSecurityReview } from "../src/review/pipeline.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

type File = { path: string; content: string };

function outcomes(files: File[]): Map<string, CheckOutcome & { detector: string }> {
  const snapshot = snapshotFromFiles(files);
  return runProjectChecks(snapshot, buildInventory(snapshot));
}

const statusOf = (files: File[], itemId: string): string =>
  outcomes(files).get(itemId)?.status ?? "missing";

const SERVER: File = {
  path: "server/src/index.ts",
  content: [
    'import { Hono } from "hono";',
    'import { secureHeaders } from "hono/secure-headers";',
    "const app = new Hono();",
    'app.use("*", secureHeaders());',
    'app.get("/api/health", (c) => c.json({ ok: true }));',
  ].join("\n"),
};

const compose = (ports: boolean): File => ({
  path: "docker-compose.yml",
  content: [
    "services:",
    "  db:",
    "    image: postgres:18-alpine",
    ...(ports ? ["    ports:", '      - "5432:5432"'] : []),
    "    volumes:",
    "      - db-data:/var/lib/postgresql/data",
    "  api:",
    "    build: .",
  ].join("\n"),
});

// --- the three outcomes ------------------------------------------------------

test("a check that cannot run reports not-applicable, never pass", () => {
  // No compose file at all: there is nothing to read, so there is nothing to
  // certify. This is the case that must never come back green.
  const outcome = outcomes([SERVER]).get("config/exposed-services");
  assert.equal(outcome?.status, "not-applicable");
  assert.ok((outcome as { reason: string }).reason.length > 20);
});

test("a not-applicable check leaves the item with the user, not passed", async () => {
  const review = await runSecurityReview(snapshotFromFiles([SERVER]));
  const item = review.modules
    .find((m) => m.id === "misconfiguration")
    ?.items.find((i) => i.id === "config/exposed-services");

  assert.equal(item?.status, "needs-your-review");
  assert.ok(item?.notApplicable, "the reason should reach the user");
  // The detector exists; it simply could not run here.
  assert.equal(item?.detector, "compose:no-public-database");
});

// --- A02 / A10 --------------------------------------------------------------------

test("a database publishing a host port is a high risk", () => {
  const outcome = outcomes([compose(true), SERVER]).get("config/exposed-services");
  assert.equal(outcome?.status, "risks");
  assert.equal((outcome as { risks: { grade: string }[] }).risks[0]?.grade, "high");
});

test("a database with no published port passes", () => {
  assert.equal(statusOf([compose(false), SERVER], "config/exposed-services"), "pass");
});

test("a published port on a non-database service is not flagged", () => {
  const web: File = {
    path: "docker-compose.yml",
    content: ["services:", "  api:", "    image: nginx", "    ports:", '      - "80:80"'].join("\n"),
  };
  assert.equal(statusOf([web, SERVER], "config/exposed-services"), "pass");
});

test("protective headers are detected when present and missed when absent", () => {
  assert.equal(statusOf([SERVER], "config/security-headers"), "pass");

  const bare: File = {
    path: "server/src/index.ts",
    content: ['import { Hono } from "hono";', "const app = new Hono();", 'app.get("/a", (c) => c.json({}));'].join("\n"),
  };
  assert.equal(statusOf([bare], "config/security-headers"), "risks");
});

test("returning an error's internal detail to the visitor is flagged", () => {
  const leaky: File = {
    path: "server/src/index.ts",
    content: [
      'import { Hono } from "hono";',
      "const app = new Hono();",
      'app.get("/a", (c) => { try { return c.json({}); } catch (err) { return c.json({ e: err.stack }); } });',
    ].join("\n"),
  };
  assert.equal(statusOf([leaky], "config/error-detail"), "risks");
  assert.equal(statusOf([SERVER], "config/error-detail"), "pass");
});

// --- A03 --------------------------------------------------------------

test("version ranges are flagged and exact pins pass", () => {
  const loose: File = {
    path: "package.json",
    content: JSON.stringify({ dependencies: { hono: "^4.13.5" } }),
  };
  const exact: File = {
    path: "package.json",
    content: JSON.stringify({ dependencies: { hono: "4.13.5" } }),
  };
  assert.equal(statusOf([loose], "components/pinned"), "risks");
  assert.equal(statusOf([exact], "components/pinned"), "pass");
});

test("a missing lockfile is flagged only when there is a manifest", () => {
  const manifest: File = { path: "package.json", content: "{}" };
  assert.equal(statusOf([manifest], "integrity/lockfile"), "risks");

  const withLock: File = { path: "bun.lock", content: "" };
  assert.equal(statusOf([manifest, withLock], "integrity/lockfile"), "pass");

  // No manifest at all: not our question to answer.
  assert.equal(statusOf([SERVER], "integrity/lockfile"), "not-applicable");
});

// --- A04 / A07 --------------------------------------------------------------

test("password storage: slow hash passes, fast hash is high risk, absent is not-applicable", () => {
  const slow: File = {
    path: "server/src/auth.ts",
    content: 'const hash = await Bun.password.hash(password, { algorithm: "argon2id" });',
  };
  const fast: File = {
    path: "server/src/auth.ts",
    content: 'const hash = createHash("sha256").update(password).digest("hex");',
  };

  assert.equal(statusOf([slow], "crypto/password-storage"), "pass");

  const flagged = outcomes([fast]).get("crypto/password-storage");
  assert.equal(flagged?.status, "risks");
  assert.equal((flagged as { risks: { grade: string }[] }).risks[0]?.grade, "high");

  assert.equal(statusOf([SERVER], "crypto/password-storage"), "not-applicable");
});

test("tokens without an expiry are flagged", () => {
  const forever: File = {
    path: "server/src/tokens.ts",
    content: 'const t = await new SignJWT({ sub: id }).setProtectedHeader({ alg: "HS256" }).sign(key);',
  };
  const expiring: File = {
    path: "server/src/tokens.ts",
    content: 'const t = await new SignJWT({ sub: id }).setExpirationTime("15m").sign(key);',
  };

  assert.equal(statusOf([forever], "auth/session-expiry"), "risks");
  assert.equal(statusOf([expiring], "auth/session-expiry"), "pass");
  assert.equal(statusOf([SERVER], "auth/session-expiry"), "not-applicable");
});

// --- A09 --------------------------------------------------------------------

test("logging a secret is a high risk; logging anything else is not", () => {
  const leaks: File = {
    path: "server/src/a.ts",
    content: "console.log(`issued token=${accessToken}`);",
  };
  const fine: File = { path: "server/src/a.ts", content: 'console.log("user signed in");' };

  const flagged = outcomes([leaks]).get("logging/no-secrets");
  assert.equal(flagged?.status, "risks");
  assert.equal((flagged as { risks: { grade: string }[] }).risks[0]?.grade, "high");
  assert.equal(statusOf([fine], "logging/no-secrets"), "pass");
});

test("a log message that only names a setting is not a leak; passing its value is", () => {
  const names: File = {
    path: "server/src/config.ts",
    content: 'if (!env.ANTHROPIC_API_KEY) console.error("AI_REVIEW=on needs ANTHROPIC_API_KEY.");',
  };
  const prints: File = { path: "server/src/config.ts", content: "console.error(env.ANTHROPIC_API_KEY);" };
  const property: File = { path: "server/src/a.ts", content: 'console.log("signed in", user.passwordHash);' };
  const labelled: File = { path: "server/src/a.ts", content: 'console.log({ password: body.pw });' };

  assert.equal(statusOf([names], "logging/no-secrets"), "pass");
  assert.equal(statusOf([prints], "logging/no-secrets"), "risks");
  assert.equal(statusOf([property], "logging/no-secrets"), "risks");
  assert.equal(statusOf([labelled], "logging/no-secrets"), "risks");
});

// --- resilience --------------------------------------------------------------

test("a check that throws is recorded as unable to run, not as a pass", () => {
  const snapshot = snapshotFromFiles([SERVER]);
  const exploding = {
    id: "test:boom",
    itemId: "config/cors",
    run: () => {
      throw new Error("boom");
    },
  };

  const result = runProjectChecks(snapshot, buildInventory(snapshot), [exploding]);
  const outcome = result.get("config/cors");

  assert.equal(outcome?.status, "not-applicable");
  assert.match((outcome as { reason: string }).reason, /could not run/);
});

test("every risk a check produces carries what, impact, fix, and no jargon", () => {
  const bad: File[] = [
    compose(true),
    { path: "package.json", content: JSON.stringify({ dependencies: { hono: "^4.0.0" } }) },
    {
      path: "server/src/a.ts",
      content: [
        'import { Hono } from "hono";',
        "const app = new Hono();",
        'app.post("/login", async (c) => {',
        '  const h = createHash("md5").update(password).digest("hex");',
        "  console.log(`token=${token}`);",
        "  return c.json({});",
        "});",
      ].join("\n"),
    },
  ];

  const risks = [...outcomes(bad).values()].flatMap((o) => (o.status === "risks" ? o.risks : []));
  assert.ok(risks.length >= 5, `expected several risks, got ${risks.length}`);

  for (const risk of risks) {
    assert.ok(risk.what.length > 20, `what too thin: ${risk.what}`);
    assert.ok(risk.impact.length > 40, `impact too thin: ${risk.impact}`);
    assert.ok(risk.fix.length > 20, `fix too thin: ${risk.fix}`);

    const prose = `${risk.what} ${risk.impact} ${risk.fix}`.toLowerCase();
    for (const jargon of ["taint", "sink", "sanitiz", "cwe", "payload"]) {
      assert.ok(!prose.includes(jargon), `leaked jargon "${jargon}" in ${risk.id}`);
    }
  }
});

// --- admin pages and password hashes ---------------------------------------------

const itemOf = async (files: Array<{ path: string; content: string }>, id: string) =>
  (await runSecurityReview(snapshotFromFiles(files))).modules.flatMap((m) => m.items).find((i) => i.id === id)!;

const USER_MODEL = {
  path: "server/models/user.js",
  content: "module.exports = (s, DataTypes) => s.define('User', { email: DataTypes.STRING, password: { type: DataTypes.STRING } });",
};

test("an admin page that only requires signing in is reported", async () => {
  const item = await itemOf([{
    path: "server/routes.js",
    content: 'router.get("/admin/users", requireLogin, (req, res) => res.json(listAll()));',
  }], "access-control/admin-only");
  assert.equal(item.status, "action-needed");
  assert.equal(item.risks[0]?.grade, "high");
});

test("an admin page with a role check passes, and says what was checked", async () => {
  for (const content of [
    'router.get("/admin/users", requireLogin, requireAdmin, (req, res) => res.json(listAll()));',
    'router.get("/admin/users", requireLogin, (req, res) => { if (req.user.role !== "admin") return res.sendStatus(403); res.json(listAll()); });',
  ]) {
    const item = await itemOf([{ path: "server/routes.js", content }], "access-control/admin-only");
    assert.equal(item.status, "pass", content);
    assert.ok(item.covers);
  }
});

test("showing the role in the page is not a role check", async () => {
  const item = await itemOf([{
    path: "server/routes.js",
    content: 'router.get("/admin", requireLogin, (req, res) => res.render("admin", { admin: req.user.role == "admin" }));',
  }], "access-control/admin-only");
  assert.equal(item.status, "action-needed");
});

test("sending whole user records with their password is reported", async () => {
  const item = await itemOf([USER_MODEL, {
    path: "server/routes.js",
    content: 'router.get("/api/users", requireLogin, (req, res) => { db.User.findAll({}).then(users => res.json({ users: users })); });',
  }], "crypto/no-password-hashes-sent");
  assert.equal(item.status, "action-needed");
});

test("leaving the password out of the lookup passes", async () => {
  const item = await itemOf([USER_MODEL, {
    path: "server/routes.js",
    content: 'router.get("/api/users", requireLogin, (req, res) => { db.User.findAll({ attributes: { exclude: ["password"] } }).then(users => res.json({ users })); });',
  }], "crypto/no-password-hashes-sent");
  assert.equal(item.status, "pass");
});

test("a webhook nobody checks the signature of is reported; a checked one passes", () => {
  const hook = 'app.post("/api/webhooks/stripe", async (c) => { const event = await c.req.json(); await markPaid(event); return c.json({ ok: true }); });';
  const open = outcomes([{ path: "server/src/index.ts", content: hook }]).get("integrity/webhook-signatures");
  assert.equal(open?.status, "risks");
  const checked = outcomes([{
    path: "server/src/index.ts",
    content: `const sig = c.req.header("stripe-signature"); stripe.webhooks.constructEvent(raw, sig, secret);\n${hook}`,
  }]).get("integrity/webhook-signatures");
  assert.equal(checked?.status, "pass");
  const elsewhere = outcomes([
    { path: "server/src/index.ts", content: hook },
    { path: "server/src/verify.ts", content: "export const ok = (raw, sig) => crypto.timingSafeEqual(createHmac('sha256', k).update(raw).digest(), sig);" },
  ]).get("integrity/webhook-signatures");
  assert.equal(elsewhere?.status, "not-applicable");
  const none = outcomes([{ path: "server/src/index.ts", content: 'app.get("/x", (c) => c.json({}));' }]).get("integrity/webhook-signatures");
  assert.equal(none?.status, "not-applicable");
});

test("a login's jwt.verify does not pass a webhook, and other real checks are not risks", () => {
  const hook = 'app.post("/api/webhooks/orders", async (c) => { const event = await c.req.json(); await markPaid(event); return c.json({ ok: true }); });';
  const status = (extra: string) =>
    outcomes([{ path: "server/src/index.ts", content: `${extra}\n${hook}` }]).get("integrity/webhook-signatures")?.status;
  assert.equal(status('app.post("/login", async (c) => { jwt.verify(token, key); });'), "risks");
  assert.equal(status("const ok = await shopify.webhooks.validate({ rawBody, rawRequest });"), "pass");
  assert.equal(status("razorpay.validateWebhookSignature(body, signature, secret);"), "pass");
  assert.equal(status('if (c.req.header("authorization") !== `Bearer ${env.HOOK_SECRET}`) return c.text("no", 401);'), "not-applicable");
});

test("unserialize counts only when it comes from node-serialize", () => {
  const kinds = (prelude: string) =>
    buildInventory(snapshotFromFiles([{ path: "server/a.js", content: `${prelude}\nconst v = serialize.unserialize(text);` }])).sinks.map((s) => s.kind);
  assert.deepEqual(kinds('const serialize = require("node-serialize");'), ["unsafe-decoding"]);
  assert.deepEqual(kinds('const serialize = require("php-serialize");'), []);
});

const itemStatus = (files: File[], item: string) => outcomes(files).get(item)?.status;
const manifest = (deps: Record<string, string>) => ({ path: "package.json", content: JSON.stringify({ name: "app", dependencies: deps }) });

test("Supabase tables without row rules are reported; secured ones pass", () => {
  const files = (sql: string) => [{ path: "supabase/config.toml", content: "" }, { path: "supabase/migrations/1.sql", content: sql }];
  assert.equal(itemStatus(files("create table public.notes (id int, body text);"), "access-control/database-rules"), "risks");
  assert.equal(
    itemStatus(files("create table public.notes (id int);\nalter table public.notes enable row level security;"), "access-control/database-rules"),
    "pass",
  );
  assert.equal(itemStatus(files("create table private.audit (id int);"), "access-control/database-rules"), "pass");
  assert.equal(itemStatus([{ path: "db/1.sql", content: "create table notes (id int);" }], "access-control/database-rules"), "not-applicable");
});

test("a container that runs as root is reported; USER or a nonroot image passes", () => {
  const docker = (content: string) => [{ path: "Dockerfile", content }];
  assert.equal(itemStatus(docker("FROM node:22\nCOPY . .\nCMD node server.js"), "config/container-user"), "risks");
  assert.equal(itemStatus(docker("FROM node:22 AS build\nUSER node\nFROM node:22\nCMD node s.js"), "config/container-user"), "risks");
  assert.equal(itemStatus(docker("FROM node:22\nUSER node\nCMD node s.js"), "config/container-user"), "pass");
  assert.equal(itemStatus(docker("FROM gcr.io/distroless/nodejs22-debian12:nonroot\nCMD [\"s.js\"]"), "config/container-user"), "pass");
  assert.equal(itemStatus([], "config/container-user"), "not-applicable");
});

test("development mode in what gets deployed is reported", () => {
  assert.equal(itemStatus([{ path: "Dockerfile", content: "FROM node:22\nENV NODE_ENV=development\nUSER node" }], "config/debug-off"), "risks");
  assert.equal(itemStatus([{ path: "Dockerfile", content: "FROM node:22\nENV NODE_ENV=production\nUSER node" }], "config/debug-off"), "pass");
  assert.equal(itemStatus([{ path: "compose.dev.yaml", content: "environment:\n  NODE_ENV: development" }], "config/debug-off"), "not-applicable");
});

test("multer without a size limit is reported", () => {
  const code = (opts: string) => [{ path: "server/up.js", content: `const multer = require("multer");\nconst upload = multer(${opts});` }];
  assert.equal(itemStatus(code('{ dest: "uploads/" }'), "design/upload-limits"), "risks");
  assert.equal(itemStatus(code('{ dest: "uploads/", limits: { fileSize: 1e6 } }'), "design/upload-limits"), "pass");
  assert.equal(itemStatus(code("options"), "design/upload-limits"), "pass");
});

test("a package one letter from a popular one is handed back; real names pass", () => {
  assert.equal(itemStatus([manifest({ expres: "1.0.0" })], "components/suspicious-packages"), "not-applicable");
  assert.equal(itemStatus([manifest({ lodahs: "1.0.0" })], "components/suspicious-packages"), "not-applicable");
  assert.equal(itemStatus([manifest({ express: "5.1.0", preact: "10.0.0", redux: "5.0.0" })], "components/suspicious-packages"), "pass");
});

test("public-prefixed secrets and the Supabase service key in browser code are risks", async () => {
  const { scan } = await import("../src/engine.ts");
  const ids = (path: string, content: string) =>
    scan(snapshotFromFiles([{ path, content }])).findings.map((f) => f.ruleId);
  assert.ok(ids("app/page.tsx", "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;").includes("secrets/client-exposed-env"));
  assert.deepEqual(ids("app/page.tsx", "const k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;"), []);
  assert.deepEqual(ids("app/api/pay/route.ts", "const k = process.env.NEXT_PUBLIC_STRIPE_SECRET_KEY;"), []);
  assert.ok(ids("web/src/components/Admin.tsx", "export const db = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);").includes("secrets/client-exposed-env"));
});

test("a login cookie set without httpOnly is a risk", async () => {
  const { scan } = await import("../src/engine.ts");
  const ids = (content: string) => scan(snapshotFromFiles([{ path: "server/a.js", content }])).findings.map((f) => f.ruleId);
  assert.ok(ids('res.cookie("session", id);').includes("auth/cookie-readable-by-scripts"));
  assert.ok(ids('setCookie(c, "auth_token", t, { secure: true });').includes("auth/cookie-readable-by-scripts"));
  assert.deepEqual(ids('res.cookie("session", id, { httpOnly: true, secure: true });'), []);
  assert.deepEqual(ids('res.cookie("theme", "dark");'), []);
  assert.deepEqual(ids('res.cookie("session", id, cookieOptions);'), []);
});

test("step 4 checks stay quiet on the reviewer's correct-code examples", async () => {
  const { scan } = await import("../src/engine.ts");
  const ids = (path: string, content: string) => scan(snapshotFromFiles([{ path, content }])).findings.map((f) => f.ruleId);
  // Server-side uses of the service-role key, and keys that are public by design.
  for (const path of ["lib/supabaseAdmin.ts", "scripts/seed.ts", "app/actions.ts", "src/db.ts"]) {
    assert.deepEqual(ids(path, "export const admin = createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY);"), [], path);
  }
  assert.ok(ids("app/admin.tsx", '"use client";\nconst db = createClient(url,\n  process.env.SUPABASE_SERVICE_ROLE_KEY);').includes("secrets/client-exposed-env"));
  for (const name of ["NEXT_PUBLIC_RECAPTCHA_SITE_KEY", "NEXT_PUBLIC_MAPBOX_TOKEN", "NEXT_PUBLIC_FIREBASE_API_KEY", "NEXT_PUBLIC_POSTHOG_KEY"]) {
    assert.deepEqual(ids("app/page.tsx", `const k = process.env.${name};`), [], name);
  }
  // Cookies: defaults that already protect, cookies meant for scripts, sign-out, spreads.
  const cookie = (code: string) => ids("server/a.js", code).filter((r) => r === "auth/cookie-readable-by-scripts");
  assert.deepEqual(cookie('cookies.set("session", id, { path: "/" });'), []);
  assert.deepEqual(cookie('ctx.cookies.set("session", id);'), []);
  assert.deepEqual(cookie('res.cookie("XSRF-TOKEN", t);'), []);
  assert.deepEqual(cookie('res.cookie("session", "", { maxAge: 0 });'), []);
  assert.deepEqual(cookie('res.cookie("session", id, { ...COOKIE_OPTS, maxAge });'), []);
  assert.deepEqual(cookie('res.cookie("session_expires_at", t);'), []);
  assert.equal(cookie('setCookie(c, "session", token);').length, 1, "Hono with no options sets no httpOnly");
});

test("step 4 file checks follow stages, comments and dev files", () => {
  const docker = (content: string, path = "Dockerfile") => itemStatus([{ path, content }], "config/container-user");
  assert.equal(docker("FROM node:22 AS base\nUSER node\nFROM base\nCMD node s.js"), "pass");
  assert.equal(docker("FROM --platform=linux/amd64 gcr.io/distroless/nodejs22:nonroot\nCMD [\"s.js\"]"), "pass");
  assert.equal(docker("FROM node:22\nCMD node s.js", "Dockerfile.dev"), "not-applicable");
  const debug = (content: string) => itemStatus([{ path: "Dockerfile", content }], "config/debug-off");
  assert.equal(debug("FROM node:22 AS build\nENV NODE_ENV=development\nRUN npm ci\nFROM node:22\nENV NODE_ENV=production\nUSER node"), "pass");
  assert.equal(debug("FROM node:22\n# NODE_ENV=development for local\nARG NODE_ENV=development\nUSER node"), "pass");
  const rls = (sql: string) =>
    itemStatus([{ path: "supabase/config.toml", content: "" }, { path: "supabase/migrations/1.sql", content: sql }], "access-control/database-rules");
  assert.equal(rls("-- create table public.old (id int);\ncreate function f() returns void as $$ begin create table tmp (id int); end $$ language plpgsql;"), "pass");
  assert.equal(rls("create table public.n (id int);\nalter table private.n enable row level security;"), "risks");
  assert.equal(itemStatus([manifest({ colord: "2.9.3", sqlite: "5.1.1" })], "components/suspicious-packages"), "pass");
  assert.equal(
    itemStatus([{ path: "server/up.js", content: 'const multer = require("multer");\nconst upload = multer({ ...base });' }], "design/upload-limits"),
    "pass",
  );
});
