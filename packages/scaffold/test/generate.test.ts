import assert from "node:assert/strict";
import { test } from "node:test";
import { blocksDeploy, scan, snapshotFromFiles } from "../../guardrails/src/index.ts";
import { generate } from "../src/index.ts";
import type { ScaffoldSpec } from "../src/types.ts";

const withAuth: ScaffoldSpec = { name: "demo", features: ["auth"], database: "postgres" };
const bare: ScaffoldSpec = { name: "demo", features: [], database: "none" };

const pathsOf = (r: ReturnType<typeof generate>) => r.files.map((f) => f.path);
const read = (r: ReturnType<typeof generate>, p: string) =>
  r.files.find((f) => f.path === p)?.contents ?? "";

test("generates a coherent app with accounts", () => {
  const result = generate(withAuth);
  const paths = pathsOf(result);

  for (const expected of [
    "Dockerfile",
    "docker-compose.yml",
    ".env.example",
    "app/package.json",
    "server/package.json",
    "server/src/env.ts",
    "server/src/auth/routes.ts",
    "server/migrations/001_users.sql",
  ]) {
    assert.ok(paths.includes(expected), `missing ${expected}`);
  }
  assert.deepEqual(result.warnings, []);
});

test("omitting accounts removes every auth file and dependency", () => {
  const result = generate(bare);
  assert.ok(!pathsOf(result).some((p) => p.includes("auth/")));
  assert.ok(!read(result, "server/package.json").includes("jose"));
  assert.ok(pathsOf(result).includes("server/src/index.ts"));
});

test("generated app passes its own guardrails with nothing blocking", () => {
  for (const spec of [withAuth, bare]) {
    const result = generate(spec);
    const snapshot = snapshotFromFiles(
      result.files.map((f) => ({ path: f.path, content: f.contents })),
    );
    const { findings, errors } = scan(snapshot);

    assert.deepEqual(errors, [], "rule errors");
    assert.deepEqual(
      blocksDeploy(findings).map((f) => `${f.ruleId} @ ${f.location?.path}:${f.location?.line}`),
      [],
      "blocking findings in generated app",
    );
  }
});

test("no secret is written into .env.example with a usable value", () => {
  const env = read(generate(withAuth), ".env.example");
  assert.match(env, /JWT_SECRET=CHANGE_ME__/);
  assert.match(env, /TUNNEL_TOKEN=CHANGE_ME__/);
  assert.match(env, /PORT=3000/);
});

test("the database is never published to the host", () => {
  const compose = read(generate(withAuth), "docker-compose.yml");
  const dbBlock = compose.slice(compose.indexOf("\n  db:"));
  assert.ok(!/^\s+ports:/m.test(dbBlock), "db exposes a host port");
  assert.ok(compose.includes("cloudflare/cloudflared"));
});

test("env validation refuses a wildcard origin and a short secret", () => {
  const envFile = read(generate(bare), "server/src/env.ts");
  assert.ok(envFile.includes('!value.includes("*")'));
  assert.ok(envFile.includes("min(32"));
  assert.ok(!/JWT_SECRET[^\n]*(\|\||\?\?)/.test(envFile));
});

test("dependency versions are pinned exactly, never ranged", () => {
  const pkg = JSON.parse(read(generate(withAuth), "app/package.json")) as {
    dependencies: Record<string, string>;
  };
  for (const [name, version] of Object.entries(pkg.dependencies)) {
    assert.match(version, /^\d+\.\d+\.\d+$/, `${name} is not pinned: ${version}`);
  }
});

test("conflicting module versions are reported rather than silently resolved", () => {
  const a = { id: "a", appDeps: { react: "19.2.8" }, files: () => [] };
  const b = { id: "b", appDeps: { react: "18.0.0" }, files: () => [] };
  const { warnings } = generate(bare, [a, b]);
  assert.equal(warnings.length, 1);
  assert.match(warnings[0]!, /react@18\.0\.0/);
});

test("the Dockerfile never COPYs a file the generator does not produce", () => {
  const result = generate(withAuth);
  const produced = new Set(pathsOf(result));
  const dockerfile = read(result, "Dockerfile");

  // A bare `COPY package.json bun.lock ./` fails the build on a missing file
  // before anything else runs, and a lockfile cannot be generated ahead of the
  // install that creates it. Every non-glob COPY source must therefore be a
  // file the scaffold actually emits.
  const sources = [...dockerfile.matchAll(/^COPY (?!--from)(.+) \S+$/gm)]
    .flatMap((m) => m[1]!.split(/\s+/))
    .filter((source) => !source.includes("*") && source !== ".");

  for (const source of sources) {
    assert.ok(produced.has(source), `Dockerfile copies ${source}, which is never generated`);
  }
});

test("the lockfile install is reproducible when a lockfile exists", () => {
  const dockerfile = read(generate(withAuth), "Dockerfile");
  assert.match(dockerfile, /bun install --frozen-lockfile/);
  assert.match(dockerfile, /COPY package\.json bun\.lock\* \.\//);
});

test("the README tells the user to commit the lockfile", () => {
  const readme = read(generate(withAuth), "README.md");
  assert.match(readme, /bun install/);
  assert.match(readme, /commit the lockfile/i);
});

test("generated apps rate limit their API, and sign-in more strictly", () => {
  const result = generate(withAuth);
  const server = read(result, "server/src/index.ts");
  const auth = read(result, "server/src/auth/routes.ts");

  assert.match(server, /rateLimiter\(/);
  assert.match(auth, /signInLimiter/);

  // The sign-in limit must actually be tighter than the general one, or adding
  // it bought nothing where guessing passwords is the threat.
  const general = /limit:\s*(\d+)/.exec(server)?.[1];
  const signIn = /limit:\s*(\d+)/.exec(auth)?.[1];
  assert.ok(general && signIn && Number(signIn) < Number(general), `${signIn} should be < ${general}`);
});

test("a module shadowing another's file is reported", () => {
  const a = { id: "a", files: () => [{ path: "x.ts", contents: "1" }] };
  const b = { id: "b", files: () => [{ path: "x.ts", contents: "2" }] };
  const { warnings } = generate(bare, [a, b]);
  assert.match(warnings[0]!, /b overwrites x\.ts previously written by a/);
});
