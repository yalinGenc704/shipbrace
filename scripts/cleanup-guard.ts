/**
 * Cleanup guard: proves a cleanup removed no detector, test, benchmark case
 * or `undecidable` branch. Compares a git commit (default HEAD) with the
 * files on disk now, so it sees uncommitted work.
 *
 *   node --experimental-strip-types scripts/cleanup-guard.ts [base-ref]
 *
 * Exit 0: nothing protected was lost. Exit 1: it lists each loss.
 *
 * What it checks:
 * - Tests and the benchmark are untouchable: any change to an existing file
 *   under a `test/` folder or `packages/guardrails/bench/` fails, so a test
 *   cannot be removed, skipped, emptied or have a case dropped from a loop.
 * - Checker code (`packages/guardrails/src`), with comments removed first, so
 *   commenting something out counts as removing it: every rule and check
 *   id, every checklist detector name, every member of the lists that switch
 *   detectors on or decide risk versus lead (`allRules`, `projectChecks`,
 *   `applicability`, `UNPROVEN_RULES`, ...), every kind of dangerous
 *   operation (`SinkKind`), every exported name, the strings and patterns
 *   in every ALL_CAPS constant (`NOT_A_GUARD`, `SAFE_TAG`, ...), and the
 *   number of `undecidable` per file.
 * Anything renamed or moved counts as lost: put it back or ask Murat.
 *
 * It reads names, not meaning. It cannot prove a kept detector still finds
 * what it did, and an `undecidable` count can balance (one removed, one
 * added in the same file). The unchanged tests and benchmark do the rest.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { withoutComments } from "../packages/guardrails/src/analysis/ast.ts";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const base = process.argv[2] ?? "HEAD";
const SCOPE = ["packages", "server", "cloud", "app"];

type Counts = Map<string, number>;
type Source = { files: string[]; read: (path: string) => string };

const git = (...args: string[]) => execFileSync("git", args, { cwd: ROOT, encoding: "utf8", maxBuffer: 64 << 20 });
const nulList = (out: string) => out.split("\0").filter(Boolean);

const baseSource: Source = {
  files: nulList(git("ls-tree", "-r", "-z", "--name-only", base, "--", ...SCOPE)),
  read: (path) => git("show", `${base}:./${path}`),
};
const diskSource: Source = {
  files: nulList(git("ls-files", "-z", "--cached", "--others", "--exclude-standard", "--", ...SCOPE)).filter((p) =>
    existsSync(join(ROOT, p)),
  ),
  read: (path) => readFileSync(join(ROOT, path), "utf8"),
};

const add = (counts: Counts, key: string) => counts.set(key, (counts.get(key) ?? 0) + 1);
const isFrozen = (path: string) => /(^|\/)test\//.test(path) || path.startsWith("packages/guardrails/bench/");
const isChecker = (path: string) => /^packages\/guardrails\/src\/.*\.tsx?$/.test(path);

/** Split a list body at its top-level commas (not inside brackets or quotes). */
function topLevelItems(body: string): string[] {
  const items: string[] = [];
  let depth = 0;
  let quote = "";
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (quote) {
      if (c === "\\") i++;
      else if (c === quote) quote = "";
    } else if (c === '"' || c === "'" || c === "`") quote = c;
    else if ("([{".includes(c)) depth++;
    else if (")]}".includes(c)) depth--;
    else if (c === "," && depth === 0) {
      items.push(body.slice(start, i));
      start = i + 1;
    }
  }
  items.push(body.slice(start));
  return items.map((s) => s.trim()).filter(Boolean);
}

const STRINGS = /"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'/g;
const DETECTOR_LIST = /export const (\w+): (?:Rule|ProjectCheck|Applicability)\[\] = \[([\s\S]*?)\n?\];/g;
const EXPORTED = /^export (?:async )?(?:function\*?|const|let|class|type|interface) (\w+)/gm;
/** A top-level ALL_CAPS constant, up to the next line that starts at column 0 (closing brackets aside). */
const CONSTANT = /^(?:export )?const ([A-Z][A-Z0-9_]*)\b[^=]*=([^\n]*(?:\n(?![^\s)\]}])[^\n]*)*)/gm;

function collect(source: Source) {
  const checker: Counts = new Map();
  const undecidable: Counts = new Map();
  const frozen = new Map<string, string>();

  for (const path of source.files) {
    if (isFrozen(path)) {
      frozen.set(path, source.read(path));
      continue;
    }
    if (!/\.tsx?$/.test(path)) continue;
    const text = withoutComments({ path, content: source.read(path) });

    const n = text.match(/\bundecidable\b/g)?.length ?? 0;
    for (let i = 0; i < n; i++) add(undecidable, `${path}: "undecidable"`);
    if (!isChecker(path)) continue;

    for (const m of text.matchAll(/\bid: "([^"]+)"/g)) add(checker, `id "${m[1]}" (${path})`);
    for (const m of text.matchAll(/\bdetector: "([^"]+)"/g)) add(checker, `checklist detector "${m[1]}"`);
    for (const m of text.matchAll(DETECTOR_LIST)) {
      for (const item of topLevelItems(m[2])) {
        const ids = item.startsWith("{")
          ? [...item.matchAll(/\b(id|itemId): "([^"]+)"/g)].map((x) => `${x[1]} ${x[2]}`).sort().join(", ")
          : item;
        add(checker, `${m[1]} includes ${ids}`);
      }
    }
    for (const m of text.matchAll(EXPORTED)) add(checker, `export ${m[1]} (${path})`);
    const sinkKinds = /export type SinkKind =([\s\S]*?);/.exec(text);
    for (const s of sinkKinds?.[1].match(STRINGS) ?? []) add(checker, `SinkKind ${s}`);
    for (const m of text.matchAll(CONSTANT)) {
      const body = m[2].trim();
      // A regular expression, on the same line or the next: the whole pattern must stay.
      if (body.startsWith("/")) add(checker, `${m[1]} pattern ${body.replace(/\s+/g, " ")}`);
      else for (const s of body.match(STRINGS) ?? []) add(checker, `${m[1]} includes "${s.slice(1, -1)}"`);
    }
  }
  return { checker, undecidable, frozen };
}

const before = collect(baseSource);
const after = collect(diskSource);

const lostFrom = (was: Counts, now: Counts) =>
  [...was].flatMap(([key, n]) => {
    const left = now.get(key) ?? 0;
    if (left >= n) return [];
    return [n - left > 1 ? `${key} (${n - left} of ${n})` : key];
  });

const report: [string, string[], number][] = [
  [
    "Test or benchmark files changed or deleted",
    [...before.frozen].filter(([p, text]) => after.frozen.get(p) !== text).map(([p]) => (after.frozen.has(p) ? `${p} (changed)` : `${p} (deleted)`)),
    before.frozen.size,
  ],
  ["Checker names removed (detectors, lists, kinds, exports, constants)", lostFrom(before.checker, after.checker), before.checker.size],
  ["Mentions of `undecidable` removed (a branch may be gone)", lostFrom(before.undecidable, after.undecidable), before.undecidable.size],
];

let lost = 0;
for (const [label, missing, total] of report) {
  console.log(`${label}: ${missing.length || "none"} (${total} checked)`);
  for (const line of missing) console.log(`  - ${line}`);
  lost += missing.length;
}

if (lost) {
  console.log(`\nFAIL: the cleanup lost ${lost} protected item(s) compared with ${base}. Put them back.`);
  process.exitCode = 1;
} else {
  console.log(`\nOK: nothing protected was lost compared with ${base}.`);
}
