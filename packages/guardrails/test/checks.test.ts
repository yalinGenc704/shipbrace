import assert from "node:assert/strict";
import { test } from "node:test";
import { buildInventory } from "../src/analysis/inventory.ts";
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

// --- A05 --------------------------------------------------------------------

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

// --- A06 / A08 --------------------------------------------------------------

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

// --- A02 / A07 --------------------------------------------------------------

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
