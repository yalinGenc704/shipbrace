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
