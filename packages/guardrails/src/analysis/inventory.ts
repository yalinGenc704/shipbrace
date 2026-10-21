import type { CodeLocation } from "../types.ts";

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
 * establishes what exists; the verifier decides what it means.
 *
 * This file holds only the shapes. `buildInventoryFromAst` in
 * `inventory-ast.ts` builds them from parsed code.
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
  | "environment"
  /**
   * Read back from a table or collection that a visitor's input is saved
   * into elsewhere in the app: a comment, a profile, a message. Whoever wrote
   * it controls it, for every later reader ("stored" attacks).
   */
  | "stored-data";

export type SinkKind =
  | "sql"
  | "shell"
  | "filesystem"
  | "html"
  | "redirect"
  | "outbound-request"
  | "dynamic-code"
  /** A MongoDB-style query whose filter takes a visitor's value as-is. */
  | "nosql"
  /**
   * XML parsed with outside references switched on (libxmljs `noent: true`):
   * the document can name a file on the server or an internal address and
   * have its contents pulled in (XXE).
   */
  | "xml-entities"
  /**
   * A record saved from a whole object (`User.create(req.body)`) into a
   * table with fields a visitor must not choose, such as a role or an owner.
   */
  | "mass-assignment";

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
  /**
   * True when the handler, written inline, only ever answers with fixed
   * text -- `(c) => c.notFound()`, `(req, res) => res.status(404).send("No")`.
   * It reads nothing and does nothing, so there is nothing behind it to lock.
   */
  answersOnlyFixed?: boolean;
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
  /** For mass assignment: the fields a visitor could set that they must not. */
  fields?: string[];
}

export interface Sanitizer {
  id: string;
  kind: SanitizerKind;
  /**
   * The kinds of operation this check makes safe, when its name says so:
   * `escapeHtml` protects a page, not a query or a command. Absent means the
   * name does not say, and it is credited everywhere (errs to silence).
   */
  protects?: SinkKind[];
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
  /** The right-hand side is just another name (`const data = body`): an exact copy. */
  copyOf?: string;
  /** The right-hand side is the visitor's whole request (`req.body`, `await c.req.json()`). */
  wholeRequest?: boolean;
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
  /** Reads and writes of named tables and collections, for stored data. */
  stores?: StoreAccess[];
  /**
   * Places that check or trim a visitor's whole request (or a plain copy of
   * it) before it is used: `schema.parse(form)`, `validate(req.body)`,
   * `delete form.role`. Mass assignment stays silent after one.
   */
  requestChecks?: Array<{ subject: string; at: number; path: string; doorId?: string }>;
  /** True when the project replaces `req.body` itself (validation middleware). */
  requestBodyReplaced?: boolean;
}

/**
 * One read or write of a named table or collection: a SQL statement naming
 * it, or a model method (`Comment.create`, `prisma.comment.findMany`).
 */
export interface StoreAccess {
  id: string;
  /** Table, model or collection name, lower case with a trailing "s" removed. */
  store: string;
  mode: "read" | "write";
  /**
   * For a write: each value saved, with its column ("*" when the column is
   * not named). Values that only choose which row changes are not listed.
   */
  written?: Array<{
    column: string;
    names: string[];
    range: [number, number];
    overridden?: string[];
    /** The value is a plain name (`data`), so where it came from can be looked up. */
    copyOf?: string;
    /** The value is the visitor's whole request itself. */
    wholeRequest?: boolean;
  }>;
  /** True for a model method (`User.create`) rather than SQL text. */
  model?: boolean;
  /** For a write: every column it sets, whoever's value goes in ("*" when unnamed). */
  touches?: string[];
  /** For a read: the columns returned, or "*" for all of them. */
  columns?: string[];
  /** For a read: the variable the result was put in, when there is one. */
  binding?: string;
  expression: string;
  /** Character range of the whole statement. */
  range: [number, number];
  location: CodeLocation;
  doorId?: string;
}
