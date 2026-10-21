import type { CodeLocation } from "../types.ts";
import type { Assignment, Door, Inventory, Sanitizer, Sink, TaintSource } from "./inventory.ts";

/**
 * Phase 3: the deterministic oracle.
 *
 * This answers exactly one question, and it is the only component permitted to
 * answer it: does untrusted input reach a dangerous operation without passing
 * through validation or escaping on the way?
 *
 * Why this is the authority rather than the language model: the model is a
 * hypothesis generator. It is good at imagining attacks and bad at being sure.
 * A product whose users cannot themselves tell a real vulnerability from an
 * invented one must never show them an unverified claim, so every proposal --
 * whoever made it -- is admitted only if rules can reproduce it from the
 * code. Proposals are decided by `verifyClaim` in `verify.ts`; this file is
 * the enumerating pass that runs before any model.
 *
 * Known limits, stated because a scanner that hides them is worse than one that
 * misses things:
 *  - Analysis is within a single file. A source passed into a helper in another
 *    module is not followed, and is reported as `indeterminate`, never as safe.
 *  - Aliasing is tracked through simple assignment only, to a fixpoint.
 *  - A sanitizer is credited only when it guards the specific name that reaches
 *    the sink, and appears before it.
 */

export type Verdict =
  /** Untrusted input reaches a dangerous operation unchecked. A real finding. */
  | "exploitable"
  /** The path exists but validation or escaping intervenes. Not a finding. */
  | "sanitized"
  /** No path from untrusted input to this operation. Not a finding. */
  | "unreachable"
  /** A path may exist but leaves the analysable scope. Reported as unverified. */
  | "indeterminate";

export interface TaintPath {
  id: string;
  verdict: Verdict;
  source: TaintSource;
  sink: Sink;
  door?: Door;
  /** Names the value travelled through, source binding first. */
  via: string[];
  sanitizer?: Sanitizer;
  location: CodeLocation;
}

/** Scope for a single analysis unit: one route handler, or one file's top level. */
interface Scope {
  door?: Door;
  range: [number, number];
  sources: TaintSource[];
  sinks: Sink[];
  sanitizers: Sanitizer[];
  assignments: Assignment[];
}

function positionOf(id: string): number {
  const parsed = Number(id.split(":").pop());
  return Number.isFinite(parsed) ? parsed : 0;
}

/**
 * Group the inventory by route handler. Everything outside a handler is
 * analysed as one per-file scope, because a source and sink sharing a module
 * top level can still reach each other.
 */
function scopesFor(inventory: Inventory): Scope[] {
  const scopes = new Map<string, Scope>();

  const scopeFor = (doorId: string | undefined, path: string): Scope => {
    const key = doorId ?? `file:${path}`;
    let scope = scopes.get(key);

    if (!scope) {
      const door = inventory.doors.find((d) => d.id === doorId);
      scope = {
        ...(door ? { door } : {}),
        range: door?.bodyRange ?? [0, Number.MAX_SAFE_INTEGER],
        sources: [],
        sinks: [],
        sanitizers: [],
        assignments: [],
      };
      scopes.set(key, scope);
    }
    return scope;
  };

  for (const source of inventory.sources) {
    scopeFor(source.doorId, source.location.path).sources.push(source);
  }
  for (const sink of inventory.sinks) {
    scopeFor(sink.doorId, sink.location.path).sinks.push(sink);
  }
  for (const sanitizer of inventory.sanitizers) {
    scopeFor(sanitizer.doorId, sanitizer.location.path).sanitizers.push(sanitizer);
  }
  for (const assignment of inventory.assignments) {
    scopeFor(assignment.doorId, assignment.location.path).assignments.push(assignment);
  }
  return [...scopes.values()];
}

/**
 * Expand a source's binding through simple assignments.
 *
 * `const raw = req.param("id"); const key = raw;` means a sink using `key` is
 * still reachable from the request. Without following the assignment the oracle
 * would call that unreachable and miss a real bug, so taint propagates to the
 * left-hand side of any assignment whose right-hand side is already tainted.
 *
 * Only assignments *after* the source count -- a variable assigned earlier got
 * its value from somewhere else and reusing the name is not data flow.
 */
function aliasesOf(binding: string, scope: Scope, sourceAt: number): Set<string> {
  const tainted = new Set([binding]);
  const reachable = scope.assignments.filter((a) => positionOf(a.id) > sourceAt);

  // Each pass can only add names already present in the scope, so this reaches
  // a fixpoint in at most as many passes as there are assignments.
  for (let pass = 0; pass <= reachable.length; pass++) {
    const before = tainted.size;

    for (const assignment of reachable) {
      if (assignment.from.some((name) => tainted.has(name))) tainted.add(assignment.target);
    }
    if (tainted.size === before) break;
  }
  return tainted;
}

/**
 * A sanitizer counts only if it guards a name on the path AND sits between the
 * source and the sink. One that runs afterwards validates a value that has
 * already been used, which is a real and common mistake -- crediting it would
 * hide the bug.
 */
function interveningSanitizer(
  tainted: Set<string>,
  scope: Scope,
  after: number,
  before: number,
): Sanitizer | undefined {
  return scope.sanitizers.find((sanitizer) => {
    const at = positionOf(sanitizer.id);
    if (at <= after || at >= before) return false;
    return sanitizer.guards.some((name) => tainted.has(name));
  });
}

/**
 * The check that happens in the same statement the input is read:
 * `const id = parseInt(req.params.id, 10)`. It sits before the input's own
 * position, so the search for a check *between* input and operation misses it.
 */
function checkOnArrival(source: TaintSource, scope: Scope): Sanitizer | undefined {
  if (!source.binding) return undefined;
  return scope.sanitizers.find(
    (s) =>
      s.guards[0] === source.binding &&
      s.location.line === source.location.line &&
      positionOf(s.id) <= positionOf(source.id),
  );
}

export function analyseTaint(inventory: Inventory): TaintPath[] {
  const paths: TaintPath[] = [];

  for (const scope of scopesFor(inventory)) {
    for (const sink of scope.sinks) {
      // Safe by construction -- a tagged sql template parameterises everything.
      if (sink.inherentlySafe) continue;

      const sinkAt = positionOf(sink.id);

      for (const source of scope.sources) {
        const sourceAt = positionOf(source.id);
        // A source that appears after the sink cannot have fed it.
        if (sourceAt >= sinkAt) continue;

        const binding = source.binding;
        const tainted = binding ? aliasesOf(binding, scope, sourceAt) : new Set<string>();
        const reaches = sink.operands.some((operand) => tainted.has(operand));

        // An unbound source (used inline) in the same handler as a sink whose
        // operands we could not resolve is exactly the case we cannot decide.
        if (!reaches) {
          if (!binding && sink.operands.length === 0) {
            paths.push(
              makePath("indeterminate", source, sink, scope, [source.expression], undefined),
            );
          }
          continue;
        }

        const sanitizer =
          checkOnArrival(source, scope) ?? interveningSanitizer(tainted, scope, sourceAt, sinkAt);
        paths.push(
          makePath(
            sanitizer ? "sanitized" : "exploitable",
            source,
            sink,
            scope,
            [...tainted],
            sanitizer,
          ),
        );
      }
    }
  }
  return paths;
}

function makePath(
  verdict: Verdict,
  source: TaintSource,
  sink: Sink,
  scope: Scope,
  via: string[],
  sanitizer: Sanitizer | undefined,
): TaintPath {
  return {
    id: `${source.id}->${sink.id}`,
    verdict,
    source,
    sink,
    ...(scope.door ? { door: scope.door } : {}),
    via,
    ...(sanitizer ? { sanitizer } : {}),
    location: sink.location,
  };
}

/** A hypothesis from the attack-simulation phase, awaiting verification. */
export interface AttackProposal {
  /** Route the attacker would call. */
  door: string;
  /** Which input they would control. */
  parameter: string;
  /** The value they would send. Never executed -- only used to locate the path. */
  payload: string;
  /** Sink the proposer believes it reaches. */
  expectedSink: string;
  rationale: string;
}

export interface ConfirmedAttack {
  proposal: AttackProposal;
  verdict: Verdict;
  /** Present only when the oracle reproduced the path from the code. */
  path?: TaintPath;
}
