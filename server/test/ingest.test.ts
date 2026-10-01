import assert from "node:assert/strict";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, test } from "node:test";
import { confine, ingest, PathOutsideRootError, DEFAULT_LIMITS } from "../src/ingest.ts";

let base = "";
let root = "";

before(async () => {
  base = await mkdtemp(join(tmpdir(), "aegis-ingest-"));
  root = join(base, "repos");

  await mkdir(join(root, "server", "src"), { recursive: true });
  await mkdir(join(root, "node_modules", "junk"), { recursive: true });
  await mkdir(join(root, "nested"), { recursive: true });

  await writeFile(join(root, "package.json"), JSON.stringify({ dependencies: { hono: "4.0.0" } }));
  await writeFile(
    join(root, "server", "src", "api.ts"),
    ['import { Hono } from "hono";', "const app = new Hono();"].join("\n"),
  );
  await writeFile(join(root, "node_modules", "junk", "evil.ts"), 'const k = "sk-aaaaaaaaaaaaaaaaaa";');
  await writeFile(join(root, "logo.png"), Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x00, 0x01]));
  await writeFile(join(root, "notes.bin"), Buffer.from([0x01, 0x00, 0x02]));
  await writeFile(join(root, "nested", "deep.ts"), "export const x = 1;");

  // A sibling directory sharing the root's name prefix, and a secret outside it.
  await mkdir(join(base, "repos-secret"), { recursive: true });
  await writeFile(join(base, "secret.txt"), "do not read me");
});

after(async () => {
  await rm(base, { recursive: true, force: true });
});

// --- confinement -------------------------------------------------------------

test("a path inside the root is allowed", async () => {
  const resolved = await confine(root, "server/src");
  assert.ok(resolved.includes("server"));
});

test("climbing out of the root with .. is refused", async () => {
  await assert.rejects(() => confine(root, "../secret.txt"), PathOutsideRootError);
  await assert.rejects(() => confine(root, "../../"), PathOutsideRootError);
});

test("an absolute path outside the root is refused", async () => {
  await assert.rejects(() => confine(root, join(base, "secret.txt")), PathOutsideRootError);
});

test("a sibling directory sharing the root's prefix is refused", async () => {
  // "repos-secret" starts with "repos" as a string. Without comparing on a path
  // separator this would be accepted as inside the root.
  await assert.rejects(() => confine(root, join(base, "repos-secret")), PathOutsideRootError);
});

test("a symlink pointing outside the root is refused", async (t) => {
  const link = join(root, "escape");
  try {
    await symlink(join(base, "secret.txt"), link);
  } catch {
    // Windows needs elevation for symlinks; the check itself is unchanged.
    return t.skip("symlinks not permitted in this environment");
  }
  await assert.rejects(() => confine(root, "escape"), PathOutsideRootError);
});

test("a path that does not exist is still confined", async () => {
  await assert.rejects(() => confine(root, "../nope/missing.ts"), PathOutsideRootError);
});

// --- reading -----------------------------------------------------------------

test("reads source files and skips node_modules entirely", async () => {
  const { snapshot } = await ingest(root);
  const paths = snapshot.files.map((f) => f.path);

  assert.ok(paths.includes("server/src/api.ts"));
  assert.ok(paths.includes("package.json"));
  assert.ok(paths.includes("nested/deep.ts"));
  assert.ok(!paths.some((p) => p.includes("node_modules")), "node_modules must not be read");
});

test("paths are repo-relative and forward-slashed on every platform", async () => {
  const { snapshot } = await ingest(root);
  for (const file of snapshot.files) {
    assert.ok(!file.path.includes("\\"), `backslash in ${file.path}`);
    assert.ok(!file.path.startsWith("/"), `absolute path ${file.path}`);
  }
});

test("binary and unknown files are skipped and counted", async () => {
  const { snapshot, skipped } = await ingest(root);
  const paths = snapshot.files.map((f) => f.path);

  assert.ok(!paths.includes("logo.png"));
  assert.ok(!paths.includes("notes.bin"));
  assert.ok(skipped.binaryOrUnknown > 0, "skips should be reported, not silent");
});

test("the file limit is honoured", async () => {
  const { snapshot, skipped } = await ingest(root, ".", { ...DEFAULT_LIMITS, maxFiles: 1 });
  assert.equal(snapshot.files.length, 1);
  assert.ok(skipped.overLimit > 0);
});

test("an oversized file is skipped rather than read", async () => {
  const { snapshot, skipped } = await ingest(root, ".", { ...DEFAULT_LIMITS, maxFileBytes: 10 });
  assert.ok(skipped.tooLarge > 0);
  assert.ok(snapshot.files.every((f) => f.content.length <= 10));
});

test("a folder that is not a git repository reports nothing as tracked", async () => {
  const { snapshot, isGitRepository } = await ingest(root);

  // Correct rather than conservative: if nothing is committed anywhere, the
  // rule about a committed .env must not fire.
  assert.equal(isGitRepository, false);
  assert.equal(snapshot.tracked.size, 0);
});

test("reviewing a subfolder narrows the snapshot", async () => {
  const { snapshot } = await ingest(root, "server");
  const paths = snapshot.files.map((f) => f.path);

  assert.deepEqual(paths, ["src/api.ts"]);
});

test("pointing at a file rather than a folder is rejected", async () => {
  await assert.rejects(() => ingest(root, "package.json"), /not a directory/);
});
