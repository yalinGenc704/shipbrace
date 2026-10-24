import assert from "node:assert/strict";
import { test } from "node:test";
import { runSecurityReview } from "../src/review/pipeline.ts";
import {
  checkKnownVulnerabilities,
  compareVersions,
  createOsvSource,
  installedDependencies,
  OSV_NOTICE,
} from "../src/review/vulnerabilities.ts";
import { snapshotFromFiles } from "../src/snapshot.ts";

const MANIFEST = {
  path: "package.json",
  content: JSON.stringify({ name: "demo", dependencies: { lodash: "4.17.20", hono: "4.6.0" } }),
};

const PACKAGE_LOCK = {
  path: "package-lock.json",
  content: JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "demo" },
      "node_modules/lodash": { version: "4.17.20", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.20.tgz" },
      "node_modules/hono": { version: "4.6.0", resolved: "https://registry.npmjs.org/hono/-/hono-4.6.0.tgz" },
      "node_modules/minimist": { version: "1.2.5", resolved: "https://registry.npmjs.org/minimist/-/minimist-1.2.5.tgz" },
      "node_modules/@acme/billing": { version: "2.0.0", resolved: "https://npm.acme.internal/@acme/billing/-/billing-2.0.0.tgz" },
      "node_modules/@demo/shared": { resolved: "packages/shared", link: true },
    },
  }),
};

/** A stand-in for OSV.dev that records what it was sent. */
function fakeOsv(vulns: Record<string, Array<{ id: string; severity: string; fixed?: string }>>) {
  const sent: unknown[] = [];
  const fetchImpl = (async (url: string, init?: { body?: string }) => {
    if (url.endsWith("/querybatch")) {
      const body = JSON.parse(init!.body!) as { queries: Array<{ package: { name: string }; version: string }> };
      sent.push(body);
      return Response.json({
        results: body.queries.map((q) => ({
          vulns: (vulns[`${q.package.name}@${q.version}`] ?? []).map((v) => ({ id: v.id })),
        })),
      });
    }
    const id = decodeURIComponent(url.split("/").pop()!);
    for (const [key, list] of Object.entries(vulns)) {
      const v = list.find((x) => x.id === id);
      if (!v) continue;
      const name = key.slice(0, key.lastIndexOf("@"));
      return Response.json({
        id,
        summary: `Summary of ${id}`,
        database_specific: { severity: v.severity },
        affected: [{
          package: { name, ecosystem: "npm" },
          ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, ...(v.fixed ? [{ fixed: v.fixed }] : [])] }],
        }],
      });
    }
    return new Response("not found", { status: 404 });
  }) as typeof fetch;
  return { source: createOsvSource(fetchImpl), sent };
}

test("only public packages with exact versions are read from the lockfile", () => {
  const result = installedDependencies(snapshotFromFiles([MANIFEST, PACKAGE_LOCK]));
  assert.ok("dependencies" in result);
  const names = result.dependencies.map((d) => d.name).sort();
  assert.deepEqual(names, ["hono", "lodash", "minimist"], "private and linked packages must never be sent");
  assert.equal(result.dependencies.find((d) => d.name === "minimist")?.direct, false);
  assert.equal(result.dependencies.find((d) => d.name === "lodash")?.direct, true);
});

test("bun.lock is read, trailing commas and all, and unrecognised entries are skipped", () => {
  const bunLock = {
    path: "bun.lock",
    content: [
      "{",
      '  "lockfileVersion": 1,',
      '  "workspaces": { "": { "name": "demo", "dependencies": { "hono": "4.6.0", }, }, },',
      '  "packages": {',
      '    "hono": ["hono@4.6.0", "", {}, "sha512-abc"],',
      '    "ws": ["ws@github:websockets/ws#abc123", {}, "websockets-ws-abc123"],',
      '    "internal": ["internal@1.0.0", "https://npm.acme.internal/", {}, "sha512-def"],',
      "  },",
      "}",
    ].join("\n"),
  };
  const result = installedDependencies(snapshotFromFiles([MANIFEST, bunLock]));
  assert.ok("dependencies" in result);
  assert.deepEqual(result.dependencies.map((d) => `${d.name}@${d.version}`), ["hono@4.6.0"]);
});

test("without a lockfile nothing is sent and the item goes back to the user", async () => {
  const { source, sent } = fakeOsv({});
  const outcome = await checkKnownVulnerabilities(snapshotFromFiles([MANIFEST]), source);
  assert.equal(outcome.status, "not-applicable");
  assert.equal(sent.length, 0);
});

test("with no source configured the review never contacts anything", async () => {
  const review = await runSecurityReview(snapshotFromFiles([MANIFEST, PACKAGE_LOCK]));
  const item = review.modules
    .find((m) => m.id === "supply-chain")
    ?.items.find((i) => i.id === "components/known-vulnerabilities");
  assert.equal(item?.status, "needs-your-review", "switched off must never read as a pass");
  assert.match(item?.notApplicable ?? "", /switched off/);
});

test("a flawed package becomes a graded risk with a concrete fix and the source credited", async () => {
  const { source } = fakeOsv({
    "lodash@4.17.20": [{ id: "GHSA-aaaa", severity: "HIGH", fixed: "4.17.21" }],
    "minimist@1.2.5": [{ id: "GHSA-bbbb", severity: "MODERATE", fixed: "1.2.6" }],
  });
  const review = await runSecurityReview(snapshotFromFiles([MANIFEST, PACKAGE_LOCK]), { vulnerabilities: source });
  const item = review.modules
    .find((m) => m.id === "supply-chain")
    ?.items.find((i) => i.id === "components/known-vulnerabilities");

  assert.equal(item?.status, "action-needed");
  assert.equal(item?.notice, OSV_NOTICE);
  const lodash = item?.risks.find((r) => r.what.includes("lodash"));
  assert.equal(lodash?.grade, "high");
  assert.match(lodash?.fix ?? "", /4\.17\.21/);
  const minimist = item?.risks.find((r) => r.what.includes("minimist"));
  assert.equal(minimist?.grade, "medium");
  assert.match(minimist?.what ?? "", /another package you use brings it in/);
  assert.match(minimist?.evidence ?? "", /CC-BY 4\.0/);

  for (const risk of item?.risks ?? []) {
    const prose = `${risk.what} ${risk.impact} ${risk.fix}`.toLowerCase();
    for (const jargon of ["taint", "sink", "sanitiz", "cwe", "payload"]) {
      assert.ok(!prose.includes(jargon), `leaked jargon: ${jargon}`);
    }
  }
});

test("a clean lookup passes, and still says what was sent", async () => {
  const { source, sent } = fakeOsv({});
  const review = await runSecurityReview(snapshotFromFiles([MANIFEST, PACKAGE_LOCK]), { vulnerabilities: source });
  const item = review.modules
    .find((m) => m.id === "supply-chain")
    ?.items.find((i) => i.id === "components/known-vulnerabilities");
  assert.equal(item?.status, "pass");
  assert.equal(item?.notice, OSV_NOTICE);

  // What actually left: names and versions, nothing else.
  assert.deepEqual(JSON.parse(JSON.stringify(sent[0])), {
    queries: [
      { package: { name: "lodash", ecosystem: "npm" }, version: "4.17.20" },
      { package: { name: "hono", ecosystem: "npm" }, version: "4.6.0" },
      { package: { name: "minimist", ecosystem: "npm" }, version: "1.2.5" },
    ],
  });
});

test("an unreachable database is reported as unchecked, never as clean", async () => {
  const failing = createOsvSource((async () => { throw new Error("offline"); }) as typeof fetch);
  const outcome = await checkKnownVulnerabilities(snapshotFromFiles([MANIFEST, PACKAGE_LOCK]), failing);
  assert.equal(outcome.status, "not-applicable");
  assert.match((outcome as { reason: string }).reason, /could not be reached/);
});

test("versions compare numerically, not as text", () => {
  assert.ok(compareVersions("4.17.21", "4.17.3") > 0);
  assert.ok(compareVersions("1.0.0-beta", "1.0.0") < 0);
  assert.equal(compareVersions("2.0.0", "2.0.0"), 0);
});

test("past the per-review cap, advisories are still reported, graded high, with no made-up fix", async () => {
  const ids = Array.from({ length: 302 }, (_, i) => `GHSA-${String(i).padStart(4, "0")}`);
  let detailCalls = 0;
  const fetchImpl = (async (url: string) => {
    if (url.endsWith("/querybatch")) return Response.json({ results: [{ vulns: ids.map((id) => ({ id })) }] });
    detailCalls++;
    const id = decodeURIComponent(url.split("/").pop()!);
    return Response.json({ id, summary: "low thing", database_specific: { severity: "LOW" } });
  }) as typeof fetch;
  const found = await createOsvSource(fetchImpl).lookup([{ name: "padded", version: "1.0.0", direct: true }]);
  const advisories = [...found.values()][0]!;
  assert.equal(detailCalls, 300, "only 300 looked up in full");
  assert.equal(advisories.length, 302, "none hidden");
  assert.deepEqual(advisories.filter((a) => a.unchecked).map((a) => a.grade), ["high", "high"]);
});
