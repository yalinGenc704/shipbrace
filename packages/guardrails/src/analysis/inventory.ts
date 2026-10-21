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
  | "environment";

export type SinkKind =
  | "sql"
  | "shell"
  | "filesystem"
  | "html"
  | "redirect"
  | "outbound-request"
  | "dynamic-code"
  /** A MongoDB-style query whose filter takes a visitor's value as-is. */
  | "nosql";

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
