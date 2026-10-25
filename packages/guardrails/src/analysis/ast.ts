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
  /** Where each comment sits, for telling code apart from text about code. */
  comments: Array<{ start: number; end: number }>;
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
      comments: (result.comments ?? []).map((c) => ({ start: c.start, end: c.end })),
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

/**
 * The file's text with comments and quoted prose blanked out to spaces, so a
 * pattern run over it matches only real code. Offsets and line breaks are kept,
 * so a match still points at the right line of the original.
 *
 * Quoted text is blanked only when it holds a space or a line break: that is a
 * sentence, or sample code kept as text (`"Replace \`origin: true\` with..."`,
 * a benchmark app in a template). A single word stays, because that is how
 * code names things: a package (`"express-session"`), a hash (`'md5'`), a
 * header (`"Content-Security-Policy"`).
 *
 * Meant for patterns that look for a danger. A pattern looking for a
 * protection should keep reading the whole file: a mention of one anywhere is
 * a reason to ask rather than to raise an alarm. A file that does not parse is
 * returned unchanged, which is how it was read before.
 */
export function codeOnly(file: SourceFile): string {
  const cached = codeOnlyCache.get(file);
  if (cached !== undefined) return cached;

  const parsed = parseFile(file);
  let text = file.content;
  if (parsed) {
    const ranges: Array<{ start: number; end: number }> = [...parsed.comments];
    walk(parsed.program, (node) => {
      if (node.type === "Literal" && typeof node.value === "string" && /\s/.test(node.value)) {
        ranges.push({ start: node.start + 1, end: node.end - 1 });
      } else if (node.type === "TemplateLiteral") {
        // The text pieces are found from the template's own span and its
        // expressions: the parser's spans for the pieces differ between .ts
        // and .js files, and their `raw` text drops the \r of a \r\n.
        const expressions = (node.expressions ?? []) as Node[];
        let from = node.start + 1;
        for (let i = 0; i <= expressions.length; i++) {
          const expression = expressions[i];
          const to = expression ? parsed.source.lastIndexOf("${", expression.start) : node.end - 1;
          if (to > from && /\s/.test(parsed.source.slice(from, to))) ranges.push({ start: from, end: to });
          if (expression) from = parsed.source.indexOf("}", expression.end) + 1;
        }
      }
    });
    // Rebuilt piece by piece; offsets are UTF-16 units, as string indexes are.
    ranges.sort((a, b) => a.start - b.start);
    const pieces: string[] = [];
    let at = 0;
    for (const { start, end } of ranges) {
      if (end <= at) continue;
      const from = Math.max(start, at);
      pieces.push(text.slice(at, from), text.slice(from, end).replace(/[^\r\n]/g, " "));
      at = end;
    }
    pieces.push(text.slice(at));
    text = pieces.join("");
  }
  codeOnlyCache.set(file, text);
  return text;
}

const codeOnlyCache = new WeakMap<SourceFile, string>();

/** The code-only text of each line, aligned with the original lines. */
export const codeOnlyLines = (file: SourceFile): string[] => codeOnly(file).split(/\r?\n/);
