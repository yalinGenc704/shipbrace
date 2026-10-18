import { parseSync } from "oxc-parser";
import type { CodeLocation, SourceFile } from "../types.ts";
import { redact } from "../util.ts";

/**
 * Parsing, replacing the regular expressions the analysis used to run on.
 *
 * The reason is one property: a parser knows the difference between code and a
 * string that contains code. Scanning this project with the old text-based
 * engine reported fifteen problems, and the four most serious were all the same
 * mistake -- a fixture generator and a scaffold hold sample code inside string
 * literals, and matching text cannot tell that apart from the real thing.
 *
 * It also makes two things exact that were previously guesses:
 *
 *   - Containment. "Is this value used inside that route handler" becomes a
 *     comparison of node ranges rather than a character-offset heuristic.
 *   - Tagged templates. `` sql`...${v}` `` parameterises its values and is safe;
 *     an untagged one is not. The parser distinguishes them structurally, so no
 *     amount of escaping or formatting can disguise one as the other.
 */

export interface Node {
  type: string;
  start: number;
  end: number;
  [key: string]: unknown;
}

export interface ParsedFile {
  path: string;
  source: string;
  program: Node;
  /** Syntax errors. A file that does not parse is skipped, never guessed at. */
  errors: string[];
  /** Byte offset of the first character of each line, for cheap line lookup. */
  lineStarts: number[];
}

function lineStartsOf(source: string): number[] {
  const starts = [0];
  for (let i = 0; i < source.length; i++) {
    if (source[i] === "\n") starts.push(i + 1);
  }
  return starts;
}

/**
 * Parse one file. Returns null when it cannot be parsed at all -- a file whose
 * syntax is broken is left out of the analysis rather than analysed as text,
 * because a partial guess is what produced the false positives in the first
 * place.
 */
export function parseFile(file: SourceFile): ParsedFile | null {
  // JSX needs the right extension hint; oxc infers from the filename.
  if (!/\.[cm]?[jt]sx?$/.test(file.path)) return null;

  try {
    const result = parseSync(file.path, file.content);
    const fatal = (result.errors ?? []).filter((e) => e.severity === "Error");

    // Recoverable errors still yield a usable tree; fatal ones do not.
    if (fatal.length > 0 && !result.program) return null;

    return {
      path: file.path,
      source: file.content,
      program: result.program as unknown as Node,
      errors: fatal.map((e) => e.message),
      lineStarts: lineStartsOf(file.content),
    };
  } catch {
    return null;
  }
}

/** Depth-first walk. `parents` is innermost-first. */
export function walk(
  root: Node,
  visit: (node: Node, parents: Node[]) => void,
  parents: Node[] = [],
): void {
  visit(root, parents);
  const nextParents = [root, ...parents];

  for (const key of Object.keys(root)) {
    if (key === "type" || key === "start" || key === "end") continue;
    const value = root[key];

    if (Array.isArray(value)) {
      for (const item of value) {
        if (isNode(item)) walk(item, visit, nextParents);
      }
    } else if (isNode(value)) {
      walk(value, visit, nextParents);
    }
  }
}

function isNode(value: unknown): value is Node {
  return (
    typeof value === "object" &&
    value !== null &&
    typeof (value as { type?: unknown }).type === "string"
  );
}

/** 1-indexed line containing `offset`, by binary search over line starts. */
function lineAt(parsed: ParsedFile, offset: number): number {
  const starts = parsed.lineStarts;
  let low = 0;
  let high = starts.length - 1;

  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (starts[mid]! <= offset) low = mid;
    else high = mid - 1;
  }
  return low + 1;
}

export function textOf(parsed: ParsedFile, node: Node): string {
  return parsed.source.slice(node.start, node.end);
}

/** The single line a node begins on, for display. Redacted. */
export function locationOf(parsed: ParsedFile, node: Node): CodeLocation {
  const line = lineAt(parsed, node.start);
  const raw = parsed.source.slice(
    parsed.lineStarts[line - 1] ?? node.start,
    parsed.lineStarts[line] ?? parsed.source.length,
  );

  return {
    path: parsed.path,
    line,
    excerpt: redact(raw.trim()).slice(0, 300),
  };
}

/** Dotted name of a callee or member chain: `c.req.param`, `db.query`, `fetch`. */
export function dottedName(node: unknown): string | null {
  if (!isNode(node)) return null;

  if (node.type === "Identifier") return String(node.name ?? "");

  if (node.type === "MemberExpression") {
    const object = dottedName(node.object);
    const property = node.computed ? "[]" : dottedName(node.property);
    if (object === null || property === null) return null;
    return `${object}.${property}`;
  }
  // A call in the middle of a chain, e.g. `c.req.json().then` -- keep the shape.
  if (node.type === "CallExpression") {
    const callee = dottedName(node.callee);
    return callee === null ? null : `${callee}()`;
  }
  return null;
}

/** Identifiers referenced anywhere beneath `node`, in source order, deduped. */
export function identifiersIn(node: Node): string[] {
  const names = new Set<string>();

  walk(node, (current, parents) => {
    if (current.type !== "Identifier") return;

    const parent = parents[0];

    // The property side of `a.b` is a name, not a value being passed.
    if (parent?.type === "MemberExpression" && parent.property === current && !parent.computed) {
      return;
    }
    // Likewise the key in `{ limit: 10 }` -- it labels a value, it is not one.
    if (
      (parent?.type === "Property" || parent?.type === "ObjectProperty") &&
      parent.key === current &&
      !parent.computed
    ) {
      return;
    }
    names.add(String(current.name ?? ""));
  });

  return [...names].filter(Boolean);
}

/** True when `inner` lies entirely within `outer`. */
export const contains = (outer: Node, inner: Node): boolean =>
  inner.start >= outer.start && inner.end <= outer.end;

export function isStringLiteral(node: unknown): node is Node & { value: string } {
  return isNode(node) && node.type === "Literal" && typeof node.value === "string";
}
