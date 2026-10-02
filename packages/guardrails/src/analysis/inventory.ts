import type { CodeLocation, RepoSnapshot, SourceFile } from "../types.ts";
import { isSource as isSourceFile, isTestPath, redact } from "../util.ts";

/**
 * Phase 1 of the security review: build a map of the application's attack
 * surface before reasoning about it.
 *
 * Three things are inventoried, and the distinction between them is the whole
 * basis of the later analysis:
 *
 *   Door      - a route an outsider can reach.
 *   Source    - a place where data the app did not create enters the code.
 *   Sink      - an operation that is dangerous if fed attacker-chosen data.
 *   Sanitizer - something that makes a source safe for a sink.
 *
 * Nothing here decides whether anything is a vulnerability. This phase only
 * establishes what exists; the oracle decides what it means.
 */

export type SourceKind =
  | "route-param"
  | "query-string"
  | "request-body"
  | "header"
  | "cookie"
  | "external-response"
  | "uploaded-file"
  | "repo-content"
  | "environment";

export type SinkKind =
  | "sql"
  | "shell"
  | "filesystem"
  | "html"
  | "redirect"
  | "outbound-request"
  | "dynamic-code";

export type SanitizerKind =
  | "schema-validation"
  | "parameterized-query"
  | "escaping"
  | "allowlist"
  | "path-normalization"
  | "numeric-coercion";

export interface Door {
  id: string;
  method: string;
  /** Route pattern as written, e.g. "/api/users/:id". */
  path: string;
  location: CodeLocation;
  /** Middleware names applied to this route or its prefix. */
  guards: string[];
  /** Character range of the handler body within the file, for scoping analysis. */
  bodyRange: [number, number];
  /**
   * Set when the route names its handler instead of writing it inline --
   * `router.post("/usersearch", appHandler.userSearch)` -- and that function
   * was found. The handler's code is then the route's code.
   */
  handlerRef?: string;
  handlerAt?: { path: string; range: [number, number] };
}

export interface TaintSource {
  id: string;
  kind: SourceKind;
  /** The expression that produced untrusted data, e.g. `c.req.param("id")`. */
  expression: string;
  /** Variable the value was assigned to, when it was assigned at all. */
  binding?: string;
  location: CodeLocation;
  /** Enclosing door, when the source sits inside a route handler. */
  doorId?: string;
}

export interface Sink {
  id: string;
  kind: SinkKind;
  expression: string;
  /** Identifiers appearing in the dangerous argument, in order. */
  operands: string[];
  location: CodeLocation;
  doorId?: string;
  /**
   * True when the construct is safe by design regardless of its operands --
   * a tagged `sql` template parameterises everything interpolated into it.
   */
  inherentlySafe: boolean;
}

export interface Sanitizer {
  id: string;
  kind: SanitizerKind;
  /** Identifiers this sanitizer produces or validates. */
  guards: string[];
  location: CodeLocation;
  doorId?: string;
}

/**
 * A plain variable assignment. Tracked separately from sanitizers because a
 * value can be passed along without being checked -- `const target = body;` --
 * and the oracle must follow it to the sink anyway.
 */
export interface Assignment {
  id: string;
  target: string;
  /** Identifiers on the right-hand side. */
  from: string[];
  location: CodeLocation;
  doorId?: string;
}

/**
 * A function defined in the code, so a claimed path can be followed into it.
 *
 * Finding every path through every function is expensive; checking whether one
 * specific claimed path holds is not. That asymmetry is why the verifier can
 * follow calls when the all-paths pass does not.
 */
export interface FunctionDef {
  id: string;
  /** Empty for an anonymous function assigned to nothing. */
  name: string;
  /** Parameter names, in order. */
  params: string[];
  /** Character range of the body. */
  bodyRange: [number, number];
  path: string;
}

/**
 * One call to a named function, with its arguments kept by position.
 *
 * Position matters: `countFor(owner)` must taint only `countFor`'s first
 * parameter. Matching on names alone let taint leak between unrelated functions
 * that happened to name a parameter the same thing, which reported a validated
 * route as vulnerable.
 */
export interface CallSite {
  id: string;
  callee: string;
  /** Identifiers appearing in each argument, by position. */
  args: string[][];
  path: string;
}

/**
 * A place the code asks who is signed in: `c.get("userId")`, `getSession(c)`.
 *
 * Needed to decide whether a record lookup is tied to its owner. A route that
 * never asks who is signed in cannot be checking that the record is theirs.
 */
export interface IdentityRead {
  id: string;
  expression: string;
  location: CodeLocation;
  doorId?: string;
  /**
   * Only printed or logged -- `res.render("page", { userId: req.user.id })`.
   * Showing who is signed in is not checking anything.
   */
  displayOnly?: boolean;
}

export interface Inventory {
  doors: Door[];
  sources: TaintSource[];
  sinks: Sink[];
  sanitizers: Sanitizer[];
  assignments: Assignment[];
  /** Optional so existing callers that build an Inventory literal keep working. */
  functions?: FunctionDef[];
  calls?: CallSite[];
  identities?: IdentityRead[];
}

/** Identifiers that are language or library names, never user data. */
const NOT_A_VARIABLE = new Set([
  "await", "return", "const", "let", "var", "new", "typeof", "this", "null",
  "undefined", "true", "false", "if", "else", "async", "function", "sql", "db",
  "String", "Number", "Boolean", "Object", "Array", "JSON", "Math", "Date",
]);

function identifiersIn(expression: string): string[] {
  const found = expression.match(/\b[A-Za-z_$][\w$]*\b/g) ?? [];
  const seen = new Set<string>();

  return found.filter((name) => {
    // Property accesses and call targets are not the data being passed.
    if (NOT_A_VARIABLE.has(name) || seen.has(name)) return false;
    seen.add(name);
    return true;
  });
}

function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

function locate(file: SourceFile, index: number, raw: string): CodeLocation {
  return {
    path: file.path,
    line: lineAt(file.content, index),
    excerpt: redact(raw.trim()).slice(0, 300),
  };
}

/**
 * Find the balanced `{...}` block that starts at or after `from`.
 * Returns null when the braces do not balance, which happens on minified or
 * truncated input -- the caller then treats the handler as unscoped rather
 * than guessing at a range.
 */
function balancedBlock(content: string, from: number): [number, number] | null {
  const open = content.indexOf("{", from);
  if (open === -1) return null;

  let depth = 0;
  let inString: string | null = null;

  for (let i = open; i < content.length; i++) {
    const char = content[i]!;
    const previous = content[i - 1];

    if (inString) {
      if (char === inString && previous !== "\\") inString = null;
      continue;
    }
    if (char === '"' || char === "'" || char === "`") {
      inString = char;
      continue;
    }
    if (char === "{") depth++;
    else if (char === "}") {
      depth--;
      if (depth === 0) return [open, i + 1];
    }
  }
  return null;
}

const ROUTE_RE =
  /\b(?:app|router|\w*[Rr]outes?)\s*\.\s*(get|post|put|patch|delete|all)\s*\(\s*(['"`])([^'"`]*)\2/g;

const USE_RE = /\b(?:app|router|\w*[Rr]outes?)\s*\.\s*use\s*\(\s*(?:(['"`])([^'"`]*)\1\s*,\s*)?([^)]*)\)/g;

/**
 * Middleware registered with `.use()` guards every route whose path starts with
 * its prefix. Collecting these per-prefix is what lets the oracle distinguish
 * "this route has no auth check in its body" from "this route is covered by a
 * middleware applied to its whole prefix" -- the second is the correct pattern
 * and must not be reported as missing access control.
 */
function collectGuards(content: string): Array<{ prefix: string; names: string[] }> {
  const guards: Array<{ prefix: string; names: string[] }> = [];
  USE_RE.lastIndex = 0;

  for (let m = USE_RE.exec(content); m; m = USE_RE.exec(content)) {
    const prefix = (m[2] ?? "*").replace(/\*+$/, "");
    const names = identifiersIn(m[3] ?? "").filter((n) => !/^(cors|secureHeaders|logger)$/.test(n));
    if (names.length > 0) guards.push({ prefix, names });
  }
  return guards;
}

function guardsFor(path: string, registered: Array<{ prefix: string; names: string[] }>): string[] {
  const names = new Set<string>();
  for (const guard of registered) {
    if (guard.prefix === "" || path.startsWith(guard.prefix)) {
      for (const name of guard.names) names.add(name);
    }
  }
  return [...names];
}

export function findDoors(file: SourceFile): Door[] {
  const doors: Door[] = [];
  const registered = collectGuards(file.content);
  ROUTE_RE.lastIndex = 0;

  for (let m = ROUTE_RE.exec(file.content); m; m = ROUTE_RE.exec(file.content)) {
    const method = m[1]!.toUpperCase();
    const path = m[3]!;
    const body = balancedBlock(file.content, m.index + m[0].length);

    doors.push({
      id: `${file.path}:${method}:${path}`,
      method,
      path,
      location: locate(file, m.index, m[0]),
      guards: guardsFor(path, registered),
      bodyRange: body ?? [m.index, file.content.length],
    });
  }
  return doors;
}

const SOURCE_PATTERNS: Array<{ kind: SourceKind; re: RegExp }> = [
  { kind: "route-param", re: /\breq\.param(?:s)?\s*(?:\(\s*['"`][^'"`]*['"`]\s*\)|\.\w+)/g },
  { kind: "query-string", re: /\breq\.quer(?:y|ies)\s*(?:\(\s*['"`][^'"`]*['"`]\s*\)|\.\w+|\b)/g },
  { kind: "request-body", re: /\breq\.(?:json|text|parseBody|formData|body)\s*\(?\s*\)?/g },
  { kind: "header", re: /\breq\.header\s*\(\s*['"`][^'"`]*['"`]\s*\)/g },
  { kind: "cookie", re: /\bgetCookie\s*\(\s*\w+\s*,\s*['"`][^'"`]*['"`]\s*\)/g },
  { kind: "external-response", re: /\bawait\s+fetch\s*\([^)]*\)/g },
  { kind: "uploaded-file", re: /\b(?:file|upload)\.(?:arrayBuffer|text|stream)\s*\(\s*\)/g },
];

/**
 * `const x = <source>` -- captures what the value was named.
 *
 * The trailing `[\w$.]*` absorbs the receiver that sits between the `=` and the
 * matched source expression: in `const id = c.req.param("id")` the source match
 * begins at `req`, so `c.` is still pending when the binding is looked up.
 */
const BINDING_RE =
  /(?:const|let|var)\s+(?:\{\s*([^}]*)\}|([A-Za-z_$][\w$]*))\s*=\s*(?:await\s+)?[\w$.]*$/;

export function findSources(file: SourceFile, doors: Door[]): TaintSource[] {
  const sources: TaintSource[] = [];

  for (const { kind, re } of SOURCE_PATTERNS) {
    re.lastIndex = 0;
    for (let m = re.exec(file.content); m; m = re.exec(file.content)) {
      const before = file.content.slice(Math.max(0, m.index - 120), m.index);
      const binding = BINDING_RE.exec(before);

      // Destructured bindings taint every name they introduce; the first is
      // enough to anchor the path, and the rest are recovered by name matching.
      const named = binding?.[2] ?? binding?.[1]?.split(",")[0]?.trim().split(":").pop()?.trim();
      const door = enclosingDoor(doors, m.index);

      sources.push({
        id: `${file.path}:src:${m.index}`,
        kind,
        expression: m[0].trim(),
        ...(named ? { binding: named } : {}),
        location: locate(file, m.index, m[0]),
        ...(door ? { doorId: door.id } : {}),
      });
    }
  }
  return sources;
}

/** Innermost door containing `index`, so nested handlers attribute correctly. */
function enclosingDoor(doors: Door[], index: number): Door | undefined {
  let innermost: Door | undefined;

  for (const door of doors) {
    const [start, end] = door.bodyRange;
    if (index < start || index >= end) continue;
    if (!innermost || start > innermost.bodyRange[0]) innermost = door;
  }
  return innermost;
}

const SINK_PATTERNS: Array<{ kind: SinkKind; re: RegExp; safeWhen?: RegExp }> = [
  /**
   * A template literal holding a recognisable SQL statement.
   *
   * Two keywords are required, not one: a lone `WHERE` matches any template
   * containing a variable named `where`. Newlines are excluded from the
   * character classes so a match cannot run from a backtick at the top of a
   * file to an unrelated one far below, which turned ordinary prose into
   * phantom database queries.
   */
  {
    kind: "sql",
    // `\\?` before the backtick: a generator writes its tag escaped (sql\`),
    // and without allowing for that the tag is missed and safe output reads
    // as unsafe.
    re: /(\w+)?\s*\\?`[^`\n]*\b(?:SELECT[^`\n]*?\bFROM|INSERT\s+INTO[^`\n]*?\bVALUES|UPDATE[^`\n]*?\bSET|DELETE\s+FROM)\b[^`\n]*\\?`/gi,
    safeWhen: /^(sql|db)$/,
  },
  { kind: "shell", re: /\b(?:execSync|execFileSync|exec|spawnSync|spawn)\s*\([^;]*/g },
  { kind: "filesystem", re: /\b(?:readFile|readFileSync|writeFile|writeFileSync|unlink|rm|createReadStream)\s*\([^;]*/g },
  { kind: "html", re: /dangerouslySetInnerHTML\s*=\s*\{\{[^}]*\}\}/g },
  { kind: "redirect", re: /\b(?:redirect)\s*\([^;]*/g },
  { kind: "outbound-request", re: /\bfetch\s*\(\s*(?!['"`]https?:\/\/)[^;]*/g },
  { kind: "dynamic-code", re: /\b(?:eval|new\s+Function)\s*\([^;]*/g },
];

export function findSinks(file: SourceFile, doors: Door[]): Sink[] {
  const sinks: Sink[] = [];

  for (const { kind, re, safeWhen } of SINK_PATTERNS) {
    re.lastIndex = 0;
    for (let m = re.exec(file.content); m; m = re.exec(file.content)) {
      const raw = m[0];
      const tag = m[1]?.trim();

      sinks.push({
        id: `${file.path}:sink:${m.index}`,
        kind,
        expression: raw.trim().slice(0, 200),
        operands: identifiersIn(interpolatedPart(raw)),
        location: locate(file, m.index, raw.split("\n")[0] ?? raw),
        ...(enclosingDoor(doors, m.index) ? { doorId: enclosingDoor(doors, m.index)!.id } : {}),
        inherentlySafe: Boolean(safeWhen && tag && safeWhen.test(tag)),
      });
    }
  }
  return sinks;
}

/**
 * Only the interpolated parts of a sink can carry attacker data. A literal
 * inside the query is fixed text and cannot be influenced, so restricting the
 * operand list to `${...}` contents (falling back to the call arguments) is
 * what keeps the oracle from flagging entirely constant statements.
 */
function interpolatedPart(raw: string): string {
  const interpolations = raw.match(/\$\{([^}]*)\}/g);
  if (interpolations) return interpolations.join(" ");

  const args = /\(([\s\S]*)$/.exec(raw);
  return args?.[1] ?? raw;
}

const SANITIZER_PATTERNS: Array<{ kind: SanitizerKind; re: RegExp }> = [
  { kind: "schema-validation", re: /\b(\w+)\s*=\s*\w*\.?(?:safeParse|parse)\s*\(/g },
  { kind: "numeric-coercion", re: /\b(\w+)\s*=\s*(?:Number|parseInt|parseFloat)\s*\(/g },
  { kind: "allowlist", re: /\b(\w+)\s*\.\s*(?:includes|has|indexOf)\s*\(/g },
  { kind: "path-normalization", re: /\b(\w+)\s*=\s*(?:path\.)?(?:normalize|resolve|basename)\s*\(/g },
  { kind: "escaping", re: /\b(\w+)\s*=\s*(?:escape\w*|sanitize\w*|DOMPurify\.sanitize)\s*\(/g },
];

export function findSanitizers(file: SourceFile, doors: Door[]): Sanitizer[] {
  const sanitizers: Sanitizer[] = [];

  for (const { kind, re } of SANITIZER_PATTERNS) {
    re.lastIndex = 0;
    for (let m = re.exec(file.content); m; m = re.exec(file.content)) {
      // Both the produced name and the names consumed count as guarded: a
      // schema parse guards its result, an allowlist check guards its subject.
      const tail = file.content.slice(m.index, m.index + 200);
      const guards = [m[1]!, ...identifiersIn(interpolatedPart(tail))];
      const door = enclosingDoor(doors, m.index);

      sanitizers.push({
        id: `${file.path}:san:${m.index}`,
        kind,
        guards: [...new Set(guards)],
        location: locate(file, m.index, m[0]),
        ...(door ? { doorId: door.id } : {}),
      });
    }
  }
  return sanitizers;
}

const ASSIGNMENT_RE = /(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\r\n]+)/g;

export function findAssignments(file: SourceFile, doors: Door[]): Assignment[] {
  const assignments: Assignment[] = [];
  ASSIGNMENT_RE.lastIndex = 0;

  for (let m = ASSIGNMENT_RE.exec(file.content); m; m = ASSIGNMENT_RE.exec(file.content)) {
    const door = enclosingDoor(doors, m.index);
    assignments.push({
      id: `${file.path}:asg:${m.index}`,
      target: m[1]!,
      from: identifiersIn(m[2]!),
      location: locate(file, m.index, m[0]),
      ...(door ? { doorId: door.id } : {}),
    });
  }
  return assignments;
}

export function buildInventory(snapshot: RepoSnapshot): Inventory {
  const inventory: Inventory = {
    doors: [],
    sources: [],
    sinks: [],
    sanitizers: [],
    assignments: [],
  };

  for (const file of snapshot.files) {
    if (!isSourceFile(file.path) || isTestPath(file.path)) continue;

    const doors = findDoors(file);
    inventory.doors.push(...doors);
    inventory.sources.push(...findSources(file, doors));
    inventory.sinks.push(...findSinks(file, doors));
    inventory.sanitizers.push(...findSanitizers(file, doors));
    inventory.assignments.push(...findAssignments(file, doors));
  }
  return inventory;
}
