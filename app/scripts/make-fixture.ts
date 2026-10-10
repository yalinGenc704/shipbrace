import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { runSecurityReview, snapshotFromFiles } from "@aegis/guardrails";

/**
 * Generates the sample review the dashboard renders until the server exists.
 *
 * It runs the real pipeline over a deliberately flawed app rather than hand-
 * writing JSON, so the UI is always built against output the engine actually
 * produces. A hand-made fixture drifts from the engine silently and the first
 * person to notice is a user looking at a broken screen.
 */

// Shaped like a real key, so the sample shows that problem; assembled here so
// this script never holds one whole and Aegis does not report itself.
const SAMPLE_KEY = ["sk", "liveT4kQ9wZr7Lm2Xc8Vb5Nd3"].join("-");

const SAMPLE = [
  'import { Hono } from "hono";',
  'import { execSync } from "node:child_process";',
  "",
  "const app = new Hono();",
  "",
  'app.get("/api/reports/:id", async (c) => {',
  '  const id = c.req.param("id");',
  "  const rows = await db.query(`SELECT * FROM reports WHERE id = ${id}`);",
  "  return c.json(rows);",
  "});",
  "",
  'app.post("/api/admin/purge", async (c) => {',
  "  const body = await c.req.json();",
  "  execSync(`rm -rf ${body.path}`);",
  "  return c.json({ ok: true });",
  "});",
  "",
  'app.get("/api/preview", async (c) => {',
  '  const target = c.req.query("url");',
  "  const upstream = await fetch(target);",
  "  return c.text(await upstream.text());",
  "});",
  "",
  `const OPENAI_KEY = "${SAMPLE_KEY}";`,
].join("\n");

const CLIENT = [
  'import { useState } from "react";',
  "",
  "export function Profile({ bio }: { bio: string }) {",
  "  return <div dangerouslySetInnerHTML={{ __html: bio }} />;",
  "}",
].join("\n");

const review = await runSecurityReview(
  snapshotFromFiles([
    { path: "server/src/api.ts", content: SAMPLE },
    { path: "app/src/Profile.tsx", content: CLIENT },
  ]),
);

const here = dirname(fileURLToPath(import.meta.url));
const out = join(here, "..", "src", "fixtures", "review.json");

writeFileSync(out, `${JSON.stringify(review, null, 2)}\n`);

const { high, medium, low, awaitingReview, clear } = review.summary;
console.log(
  `wrote ${out}\n  high=${high} medium=${medium} low=${low} awaiting=${awaitingReview} clear=${clear}/10`,
);
