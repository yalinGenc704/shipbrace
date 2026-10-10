import assert from "node:assert/strict";
import { test } from "node:test";
import { blocksDeploy, scan } from "../src/engine.ts";
import { renderAuto, renderSupervise } from "../src/report.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";
import { redact } from "../src/util.ts";

const file = (path: string, content: string) => ({ path, content });

// Shaped like real keys, but assembled here so this file never holds one whole:
// Aegis reviews its own code, and a test fixture should not read as a leak.
const OPENAI_KEY = ["sk", "Q7vR2mX9pL4tW8nK3sB6"].join("-");
const GITHUB_TOKEN = ["ghp", "Zr4Kq9Lm2Xv8Tn5Wb7Pc3Hd6Jf1Sg0Ya4Ue9"].join("_");

test("flags a hardcoded provider token", () => {
  const { findings } = scan(
    snapshotFromFiles([file("server/src/ai.ts", `const key = "${OPENAI_KEY}";`)]),
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.ruleId, "secrets/hardcoded-credential");
  assert.equal(findings[0]?.severity, "critical");
});

test("redacts the secret out of the reported excerpt", () => {
  const { findings } = scan(
    snapshotFromFiles([file("server/src/ai.ts", `const key = "${OPENAI_KEY}";`)]),
  );
  const excerpt = findings[0]?.location?.excerpt ?? "";
  assert.ok(!excerpt.includes("Q7vR2mX9pL4tW8nK3sB6"), `excerpt leaked the key: ${excerpt}`);
});

test("obvious placeholders are not reported as leaked keys", () => {
  const placeholders = [
    'const key = "sk-your-key-here-replace-me";',
    'const key = "sk-xxxxxxxxxxxxxxxxxxxxxxxx";',
    'const key = "sk-abcdefghijklmnop1234";',
    'const aws = "AKIAIOSFODNN7EXAMPLE";',
  ];
  for (const line of placeholders) {
    const { findings } = scan(snapshotFromFiles([file("server/src/ai.ts", line)]));
    assert.deepEqual(findings, [], line);
  }
});

test("does not flag .env.example", () => {
  const { findings } = scan(
    snapshotFromFiles([file(".env.example", "JWT_SECRET=replace-me")]),
  );
  assert.deepEqual(findings, []);
});

test("flags a committed .env only when git tracks it", () => {
  const files = [file(".env", "DATABASE_PASSWORD=hunter2")];
  assert.equal(scan(snapshotFromFiles(files, [])).findings.length, 0);
  assert.equal(scan(snapshotFromFiles(files, [".env"])).findings.length, 1);
});

test("flags untagged SQL interpolation but not the postgres tagged template", () => {
  const unsafe = scan(snapshotFromFiles([
    file("server/src/q.ts", "const r = await db.query(`SELECT * FROM users WHERE id = ${id}`);"),
  ]));
  assert.equal(unsafe.findings[0]?.ruleId, "injection/sql-string-building");

  const safe = scan(snapshotFromFiles([
    file("server/src/q.ts", "const r = await sql`SELECT * FROM users WHERE id = ${id}`;"),
  ]));
  assert.deepEqual(safe.findings, []);
});

test("flags a JWT secret fallback", () => {
  const { findings } = scan(snapshotFromFiles([
    file("server/src/auth.ts", 'const s = process.env.JWT_SECRET || "dev-secret";'),
  ]));
  assert.equal(findings[0]?.ruleId, "auth/default-jwt-secret");
});

test("ignores VITE_ vars that are explicitly publishable", () => {
  const flagged = scan(snapshotFromFiles([
    file("app/src/a.ts", "const k = import.meta.env.VITE_STRIPE_SECRET_KEY;"),
  ]));
  assert.equal(flagged.findings.length, 1);

  const ok = scan(snapshotFromFiles([
    file("app/src/a.ts", "const k = import.meta.env.VITE_STRIPE_PUBLISHABLE_KEY;"),
  ]));
  assert.deepEqual(ok.findings, []);
});

test("skips node_modules entirely", () => {
  const { findings, filesScanned } = scan(snapshotFromFiles([
    file("node_modules/pkg/index.js", 'const k = "sk-abcdefghijklmnop1234";'),
  ]));
  assert.deepEqual(findings, []);
  assert.equal(filesScanned, 0);
});

test("one throwing rule does not abort the scan", () => {
  const exploding = {
    id: "test/boom",
    category: "architecture" as const,
    severity: "low" as const,
    appliesTo: () => true,
    check: () => {
      throw new Error("boom");
    },
  };
  const result = scan(snapshotFromFiles([file("a.ts", "const x = 1;")]), [exploding]);
  assert.equal(result.errors.length, 1);
  assert.equal(result.errors[0]?.ruleId, "test/boom");
});

test("findings are sorted most severe first", () => {
  const { findings } = scan(snapshotFromFiles([
    file("app/src/a.tsx", "<div dangerouslySetInnerHTML={{ __html: bio }} />"),
    file("server/src/b.ts", `const k = "${GITHUB_TOKEN}";`),
  ]));
  assert.equal(findings[0]?.severity, "critical");
  assert.equal(findings.at(-1)?.severity, "high");
});

test("auto mode reports no code, supervise mode reports the line", () => {
  const { findings } = scan(snapshotFromFiles([
    file("server/src/ai.ts", `const key = "${OPENAI_KEY}";`),
  ]));

  const auto = renderAuto(findings);
  assert.equal(auto.ok, false);
  assert.equal(auto.needsYou.length, 1);
  assert.ok(!JSON.stringify(auto).includes("server/src/ai.ts"), "auto mode leaked a file path");

  const supervise = renderSupervise(findings);
  assert.equal(supervise.summary.critical, 1);
  assert.equal(supervise.items[0]?.location?.path, "server/src/ai.ts");
  assert.equal(supervise.items[0]?.blocking, true);
});

test("low-confidence high findings do not block deploy", () => {
  const { findings } = scan(snapshotFromFiles([
    file("app/src/a.tsx", "<div dangerouslySetInnerHTML={{ __html: bio }} />"),
  ]));
  assert.equal(findings[0]?.confidence, "possible");
  assert.deepEqual(blocksDeploy(findings), []);
});

test("redact handles JWTs and key-value pairs", () => {
  assert.ok(!redact('password: "s3cr3tvalue"').includes("s3cr3tvalue"));
  assert.ok(redact("eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2Q").includes("[redacted-jwt]"));
});
