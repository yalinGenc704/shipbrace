import type { RepoSnapshot, SourceFile } from "../types.ts";
import { redact } from "../util.ts";
import { dottedName, parseFile, walk, type Node, type ParsedFile } from "./ast.ts";
import { MAX_CLEANER_CODE, MAX_QUESTIONS, plainReason } from "./cleaner-judge.ts";
import type { SinkKind } from "./inventory.ts";
import type { TaintPath } from "./oracle.ts";

/**
 * The app's own "cleaning" functions on a traced path, so a model can read
 * them (2026-11-10, an optional step measured on the benchmark's home-made
 * cleaner cases).
 *
 * The rules recognise cleaners by name, and only when the result is assigned:
 * `const name = escapeSql(raw)` is trusted whatever escapeSql does, and
 * `toSafeId(raw)` or a cleaner called inside the query is not seen at all.
 * Here every call between the visitor's value and the dangerous operation is
 * found -- assigned or inline -- and, when the function is written in this
 * repository, its code is kept for the question. A library function has no
 * code to read and is left to the rules.
 */

export interface CleanerUse {
  /** The traced path this cleaner sits on. */
  path: TaintPath;
  /** The short id its question was asked under (`q1`, `q2`...), once asked. */
  askedAs?: string;
  /** Stable for one function and one place it feeds: the question asked about it. */
  questionId: string;
  name: string;
  /** Where the function is written, and its source. */
  definedIn: string;
  code: string;
  sinkKind: SinkKind;
  /** The dangerous line, so "a page" can be told apart from "a link's address". */
  usedIn: string;
}

/** What a model said about one cleaner in one place. */
export interface CleanerVerdict {
  protects: boolean;
  /** One plain sentence: what gets through, or why nothing does. */
  reason: string;
}

export interface CleanerQuestion {
  id: string;
  name: string;
  code: string;
  feeds: SinkKind;
  usedIn: string;
}

/**
 * Reads cleaners and says whether each makes its value safe where it is used.
 * Provider-agnostic like the proposer; `createClaudeCleanerJudge` is the
 * default. Answers it gives for questions it was not asked are ignored.
 */
export interface CleanerJudge {
  name: string;
  judge(questions: CleanerQuestion[]): Promise<Map<string, CleanerVerdict>>;
}

const offsetOf = (id: string): number => {
  const parsed = Number(id.split(":").pop());
  return Number.isFinite(parsed) ? parsed : -1;
};

const fileOf = (id: string): string => id.split(":").slice(0, -2).join(":");

export function findCleaners(snapshot: RepoSnapshot, paths: TaintPath[]): CleanerUse[] {
  const parsedCache = new Map<string, ParsedFile | null>();
  const parsed = (path: string): ParsedFile | null => {
    if (!parsedCache.has(path)) {
      const file = snapshot.files.find((f) => f.path === path);
      parsedCache.set(path, file ? parseFile(file) : null);
    }
    return parsedCache.get(path) ?? null;
  };

  const uses: CleanerUse[] = [];
  for (const path of paths) {
    if (path.verdict !== "exploitable" && path.verdict !== "sanitized") continue;
    const file = parsed(path.sink.location.path);
    if (!file) continue;

    const call = cleanerCall(file, path);
    if (!call) continue;
    const name = dottedName(call.callee) ?? "";
    const definition = definitionOf(snapshot, parsed, file, name);
    if (!definition) continue;

    const usedIn = redact(path.sink.expression);
    uses.push({
      path,
      questionId: `${definition.path}#${name}@${path.sink.kind}:${usedIn}`,
      name,
      definedIn: definition.path,
      code: definition.code,
      sinkKind: path.sink.kind,
      usedIn,
    });
  }
  return uses;
}

/**
 * The call that stands between the visitor's value and the operation.
 *
 * On a path the rules call cleaned, it is the cleaner they credited. On one
 * they call open, it must be the only way the value reaches the operation,
 * inside the same handler: a call written inside the dangerous expression
 * that holds every use of the value there, or a call whose result is
 * assigned to the one name the operation uses for it. A helper elsewhere in
 * the file, or a cleaned copy used beside the raw value, is not asked about:
 * a "works" answer about code the value does not pass through would soften
 * a real finding. A longer chain (`const a = clean(x); const b = a + "!"`)
 * is not followed either; the rules' answer stands.
 */
function cleanerCall(file: ParsedFile, path: TaintPath): Node | undefined {
  const sourceAt = offsetOf(path.source.id);
  const sinkAt = offsetOf(path.sink.id);
  const via = new Set(path.via);

  if (path.verdict === "sanitized") {
    const at = path.sanitizer ? offsetOf(path.sanitizer.id) : -1;
    if (at < 0 || fileOf(path.sanitizer!.id) !== path.sink.location.path) return undefined;
    let found: Node | undefined;
    walk(file.program, (node) => {
      if (node.type !== "CallExpression" || node.start < at || node.start > at + 400) return;
      if (!found || node.start < found.start) found = node;
    });
    return found;
  }

  // The operation's node and the function that holds it.
  let sink: Node | undefined;
  let handler: Node | undefined;
  walk(file.program, (node, parents) => {
    if (sink || node.start !== sinkAt) return;
    sink = node;
    handler = parents.find((p) => FUNCTION.test(p.type));
  });
  if (!sink || !handler) return undefined;
  const inside = (outer: Node, at: number) => outer.start <= at && at < outer.end;

  // Every value the operation uses: the source, and every name in its
  // dangerous part. Any of them might carry the visitor's value (one path's
  // names are not all of them), so all must go through the cleaner.
  const operands = new Set(path.sink.operands);
  const uses: Array<{ at: number; name?: string }> = [];
  if (inside(sink, sourceAt)) uses.push({ at: sourceAt });
  walk(sink, (node, parents) => {
    if (node.type !== "Identifier") return;
    const named = String(node.name);
    if (!via.has(named) && !operands.has(named)) return;
    if (parent0IsCallee(node, parents)) return;
    const parent = parents[0];
    if (parent?.type === "MemberExpression" && parent.property === node && !parent.computed) return;
    if ((parent?.type === "Property" || parent?.type === "ObjectProperty") && parent.key === node && !parent.computed) return;
    uses.push({ at: node.start, name: String(node.name) });
  });
  if (uses.length === 0) return undefined;

  let found: Node | undefined;
  walk(handler, (node, parents) => {
    if (found || node.type !== "CallExpression") return;
    if (node.start === sourceAt || node.start === sinkAt) return; // The source or the operation itself.
    const args = (node.arguments ?? []) as Node[];
    const takesValue = args.some((arg) =>
      inside(arg, sourceAt) || (arg.type === "Identifier" && via.has(String(arg.name)))
    );
    if (!takesValue) return;

    // Inline: every use of the value in the operation is inside this call.
    if (inside(sink!, node.start)) {
      if (uses.every((u) => inside(node, u.at))) found = node;
      return;
    }
    // Assigned: the operation uses only this name for the value, and nothing
    // in the handler changes that name afterwards.
    const declarator = parents[0]?.type === "VariableDeclarator" && parents[0].init === node
      ? (parents[0].id as Node | undefined)
      : undefined;
    if (declarator?.type !== "Identifier" || node.start > sinkAt) return;
    const name = String(declarator.name);
    if (!uses.every((u) => u.name === name)) return;
    // The name the operation uses must be this one: declared once in the
    // handler, never written again, in a block that holds the operation.
    const bound = bindings(handler!, name);
    const block = parents.find((p) => BLOCK.test(p.type));
    if (bound.declared === 1 && bound.written === 0 && block && inside(block, sinkAt)) found = node;
  });
  return found;
}

const FUNCTION = /^(?:ArrowFunctionExpression|FunctionExpression|FunctionDeclaration)$/;
const BLOCK = /^(?:BlockStatement|Program|ArrowFunctionExpression)$/;

/**
 * How often a name is bound under `root` (declarations at any depth,
 * parameters, catch clauses, imports, classes) and written after that
 * (assignments, destructuring, ++/--, for...in/of). Read by name, not scope:
 * a name bound twice can't be told apart, so it is never trusted.
 */
function bindings(root: Node, name: string): { declared: number; written: number } {
  let declared = 0;
  let written = 0;
  const count = (pattern: unknown, into: "declared" | "written") => {
    if (typeof pattern !== "object" || pattern === null) return;
    walk(pattern as Node, (n, parents) => {
      if (n.type !== "Identifier" || n.name !== name) return;
      // `{ key: value }` in a pattern binds the value, not the key.
      const parent = parents[0];
      if (parent && /^(?:Property|ObjectProperty)$/.test(parent.type) && parent.key === n && parent.value !== n) return;
      if (into === "declared") declared++;
      else written++;
    });
  };
  walk(root, (node) => {
    switch (node.type) {
      case "VariableDeclarator":
        count(node.id, "declared");
        break;
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        if (node.id) count(node.id, "declared");
        for (const param of (node.params ?? []) as Node[]) count(param, "declared");
        break;
      case "CatchClause":
        count(node.param, "declared");
        break;
      case "ClassDeclaration":
        count(node.id, "declared");
        break;
      case "ImportSpecifier":
      case "ImportDefaultSpecifier":
      case "ImportNamespaceSpecifier":
        count(node.local, "declared");
        break;
      case "AssignmentExpression":
        count(node.left, "written");
        break;
      case "UpdateExpression":
        count(node.argument, "written");
        break;
      case "ForInStatement":
      case "ForOfStatement":
        if ((node.left as Node | undefined)?.type !== "VariableDeclaration") count(node.left, "written");
        break;
    }
  });
  return { declared, written };
}

/** The name of the function being called (`clean` in `clean(x)`), not a value. */
const parent0IsCallee = (node: Node, parents: Node[]): boolean =>
  parents[0]?.type === "CallExpression" && parents[0].callee === node;

/**
 * The function's own code, when it is written in this repository: declared
 * once at the top of its file (a name declared twice, or only inside another
 * function, is not read -- it may not be the one called), or imported by name
 * from another file of the repository.
 */
function definitionOf(
  snapshot: RepoSnapshot,
  parsed: (path: string) => ParsedFile | null,
  file: ParsedFile,
  name: string,
): { path: string; code: string } | undefined {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return undefined;
  // One binding of the name in the whole file -- a top-level definition or
  // an import -- and never written: otherwise the function that runs may be
  // a different one (a parameter, a local look-alike) from the one read.
  const bound = bindings(file.program, name);
  if (bound.declared !== 1 || bound.written !== 0) return undefined;

  const local = definedHere(file, name);
  if (local !== undefined) return local ? { path: file.path, code: local } : undefined;

  // `import { clean } from "./util"` or `import { a as clean }`: look up the
  // name that file exports.
  let from: string | undefined;
  let exported: string | undefined;
  walk(file.program, (node) => {
    if (from || node.type !== "ImportDeclaration") return;
    const source = String((node.source as Node | undefined)?.value ?? "");
    for (const specifier of (node.specifiers ?? []) as Node[]) {
      if (specifier.type !== "ImportSpecifier" || (specifier.local as Node | undefined)?.name !== name) continue;
      const imported = specifier.imported as Node | undefined;
      exported = String(imported?.name ?? imported?.value ?? "");
      if (source.startsWith(".")) from = source;
    }
  });
  if (!from || !exported) return undefined;
  const base = joinPath(file.path, from);
  const stem = base.replace(/\.[cm]?js$/, "");
  for (const candidate of [base, `${stem}.ts`, `${stem}.js`, `${stem}.tsx`, `${stem}/index.ts`, `${stem}/index.js`]) {
    const other = snapshot.files.some((f: SourceFile) => f.path === candidate) ? parsed(candidate) : null;
    const code = other ? definedHere(other, exported) : undefined;
    if (code) return { path: candidate, code };
  }
  return undefined;
}

/**
 * The top-level function `name` in this file: its code, "" when the name is
 * declared more than once (which one runs can't be told), or undefined when
 * it is not declared here at all.
 */
function definedHere(file: ParsedFile, name: string): string | undefined {
  const found: string[] = [];
  for (let statement of (file.program.body ?? []) as Node[]) {
    if (/^Export(?:Named|Default)Declaration$/.test(statement.type) && statement.declaration) {
      statement = statement.declaration as Node;
    }
    if (statement.type === "FunctionDeclaration" && (statement.id as Node | undefined)?.name === name) {
      found.push(file.source.slice(statement.start, statement.end));
    }
    if (statement.type === "VariableDeclaration") {
      for (const declarator of (statement.declarations ?? []) as Node[]) {
        if ((declarator.id as Node | undefined)?.name !== name) continue;
        const init = declarator.init as Node | undefined;
        found.push(init && /^(?:ArrowFunctionExpression|FunctionExpression)$/.test(init.type)
          ? file.source.slice(declarator.start, declarator.end)
          : "");
      }
    }
  }
  if (found.length === 0) return undefined;
  if (found.length > 1 || !found[0]) return "";
  // It is sent to a model: secrets in it are hidden before it is cut, so a
  // secret across the cut is still caught.
  return redact(found[0]).slice(0, MAX_CLEANER_CODE);
}

function joinPath(from: string, relative: string): string {
  const parts = from.split("/").slice(0, -1);
  for (const piece of relative.split("/")) {
    if (piece === "..") parts.pop();
    else if (piece !== ".") parts.push(piece);
  }
  return parts.join("/");
}

/**
 * One question per function and place, however many paths share it, under a
 * short id the model only has to copy back. At most `max` are asked.
 */
export function questionsFor(uses: CleanerUse[], max = MAX_QUESTIONS): CleanerQuestion[] {
  const seen = new Map<string, CleanerQuestion>();
  for (const use of uses) {
    let question = seen.get(use.questionId);
    if (!question) {
      if (seen.size >= max) continue;
      question = { id: `q${seen.size + 1}`, name: use.name, code: use.code, feeds: use.sinkKind, usedIn: use.usedIn };
      seen.set(use.questionId, question);
    }
    use.askedAs = question.id;
  }
  return [...seen.values()];
}

/**
 * The one-way rule (Murat's decision, 2026-11-10), with the rules keeping
 * the last word on what a path is:
 *
 *  - The model says a cleaner the rules trusted does not work. The rules then
 *    trace the path again without that one cleaner (`recheck`); only if the
 *    value then reaches the operation unchecked is the path a finding,
 *    labelled as the model's reading. Any other check on the way still counts.
 *  - The model says a cleaner the rules did not see works. The finding
 *    becomes "worth a look", never silence or a pass, so a wrong "works"
 *    never hides a problem.
 *
 * Returns how many paths each answer changed.
 */
export function applyVerdicts(
  uses: CleanerUse[],
  verdicts: Map<string, CleanerVerdict>,
  recheck: (use: CleanerUse) => boolean,
): { broken: number; working: number } {
  let broken = 0;
  let working = 0;
  for (const use of uses) {
    const verdict = use.askedAs ? verdicts.get(use.askedAs) : undefined;
    if (!verdict) continue;
    // Whatever judge answered, its sentence is made fit for the report here:
    // one plain sentence, no code marks, none of the words the report avoids.
    const cleaner = { name: use.name, protects: verdict.protects, reason: plainReason(verdict.reason, verdict.protects) };
    if (use.path.verdict === "sanitized" && !verdict.protects && recheck(use)) {
      use.path.verdict = "exploitable";
      use.path.cleaner = cleaner;
      broken++;
    } else if (use.path.verdict === "exploitable" && verdict.protects && !use.path.cleaner) {
      use.path.cleaner = cleaner;
      working++;
    }
  }
  return { broken, working };
}
