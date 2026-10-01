import type { CodeLocation } from "../types.ts";
import type {
  Assignment,
  Door,
  FunctionDef,
  Inventory,
  Sanitizer,
  Sink,
  SinkKind,
  TaintSource,
} from "./inventory.ts";

/**
 * The verifier: given a claimed way in, decide whether it actually works.
 *
 * This is the piece the architecture was always meant to have. The previous
 * oracle enumerated every path it could find and then checked whether a
 * proposal appeared on its own list -- which meant a proposal could never
 * contribute anything, because anything it named was already found. The model
 * was marking its own homework against an answer sheet the marker wrote.
 *
 * Here the direction is reversed. Something else -- a language model, a human,
 * a fuzzer -- claims "this input, on this route, reaches that operation". This
 * file decides whether that specific claim holds, using nothing but rules. No
 * model is consulted, so a confident-sounding wrong claim fails exactly as
 * loudly as an obviously wrong one.
 *
 * Verifying one claim is far cheaper than finding every path, which is what
 * makes the division of labour pay: the expensive, imprecise search happens
 * elsewhere, and the cheap, exact check happens here. That asymmetry also lets
 * the verifier follow values into other functions, which the all-paths pass
 * does not attempt.
 */

export interface Claim {
  /** Route as written, e.g. "/api/reports/:id". Optional for non-routed code. */
  door?: string;
  /** Which input is said to carry the untrusted value. Matched loosely. */
  parameter?: string;
  /** The operation it is said to reach. */
  sink: SinkKind;
  /** Where the claim came from, for reporting. Never affects the verdict. */
  origin?: string;
}

export type ClaimVerdict =
  /** The path exists and nothing checks the value on the way. A real finding. */
  | "valid"
  /** The path exists but validation or escaping intervenes. Not a finding. */
  | "blocked"
  /** No path from that input to that operation. The claim was wrong. */
  | "no-path"
  /** The claim does not correspond to code that exists. */
  | "not-found"
  /** A path may exist but leaves what can be followed. Never reported as safe. */
  | "undecidable";

export interface VerifiedClaim {
  claim: Claim;
  verdict: ClaimVerdict;
  /** Why the verdict came out that way, in one line, for the audit trail. */
  reason: string;
  source?: TaintSource;
  sink?: Sink;
  door?: Door;
  /** Names the value travelled through, in order. */
  via?: string[];
  blockedBy?: Sanitizer;
  location?: CodeLocation;
}

const within = (range: [number, number], position: number): boolean =>
  position >= range[0] && position < range[1];

function positionOf(id: string): number {
  const parsed = Number(id.split(":").pop());
  return Number.isFinite(parsed) ? parsed : 0;
}

const fileOf = (id: string): string => id.split(":")[0] ?? "";

/** The sanitizer that produced a washed name, for the audit trail. */
function washedBy(inventory: Inventory, flow: Flow): Sanitizer | undefined {
  return inventory.sanitizers.find((sanitizer) => {
    const produced = sanitizer.guards[0];
    return Boolean(produced) && flow.washed.has(produced!);
  });
}

/** Innermost function containing a position, or undefined at file top level. */
function enclosingFunctionDef(
  inventory: Inventory,
  path: string,
  position: number,
): FunctionDef | undefined {
  let innermost: FunctionDef | undefined;

  for (const fn of inventory.functions ?? []) {
    if (fn.path !== path || !within(fn.bodyRange, position)) continue;
    if (!innermost || fn.bodyRange[0] > innermost.bodyRange[0]) innermost = fn;
  }
  return innermost;
}

const enclosingFunction = (inventory: Inventory, path: string, position: number) =>
  enclosingFunctionDef(inventory, path, position)?.id;

/**
 * Propagate taint from one binding, following assignments and calls.
 *
 * Two things make this stronger than the all-paths pass:
 *
 *  - It crosses function boundaries. When a tainted value is passed to a
 *    function defined in the same file, the matching parameter becomes tainted
 *    and the search continues inside that function's body.
 *  - It is not restricted to one route handler, because the claim says where to
 *    start and where to finish.
 */
interface Flow {
  /** Names still carrying the visitor's value unchecked. */
  tainted: Set<string>;
  /**
   * Parameters carrying it, keyed by name and scoped to the functions they
   * belong to.
   *
   * A bare set cannot express this: two helpers both calling their parameter
   * `owner` are two different variables, and treating them as one attributed a
   * validated route's value to an unrelated helper's query.
   */
  taintedParams: Map<string, Set<string>>;
  washedParams: Map<string, Set<string>>;
  /**
   * Names derived from it that passed through validation.
   *
   * Kept separate rather than simply dropped so the verifier can distinguish
   * "there is no route from this input to that operation" from "there is one,
   * and a check stands in it". Both mean the claim fails, but only the second
   * tells the reader their validation is doing its job.
   */
  washed: Set<string>;
}

function taintedNames(
  start: string,
  after: number,
  path: string,
  inventory: Inventory,
): Flow {
  const tainted = new Set([start]);
  const washed = new Set<string>();
  const taintedParams = new Map<string, Set<string>>();
  const washedParams = new Map<string, Set<string>>();

  const noteParam = (into: Map<string, Set<string>>, param: string, fn: string): boolean => {
    const owners = into.get(param) ?? new Set<string>();
    const had = owners.has(fn);
    owners.add(fn);
    into.set(param, owners);
    return !had;
  };
  const assignments = inventory.assignments.filter(
    (a) => fileOf(a.id) === path && positionOf(a.id) > after,
  );
  const functions = inventory.functions ?? [];

  /**
   * Only calls that could run after the value was read.
   *
   * Unfiltered, a call in an earlier route picked up a variable of the same
   * name from a later one and carried it into a helper, attributing a finding
   * to a route that never passed that value. Filtering by position is the same
   * rule the assignments already follow.
   *
   * Limitation: a chain that continues inside a helper in another file is not
   * followed past the first hop, so such a path comes back unproven rather than
   * confirmed. Missing a real path is a gap; inventing one is a defect.
   */
  const calls = (inventory.calls ?? []).filter(
    (c) => c.path === path && positionOf(c.id) > after,
  );

  /**
   * Names a validation step produces. Taint stops at these.
   *
   * `const owner = Number(raw)` means `owner` is no longer the visitor's value;
   * it is whatever survived the check. Letting taint flow through it reported a
   * route that validates its input as vulnerable -- the worst kind of mistake,
   * because it is a warning about code that is already correct.
   */
  const cleaned = new Set(
    inventory.sanitizers
      .filter((s) => fileOf(s.id) === path && positionOf(s.id) > after)
      .map((s) => s.guards[0])
      .filter((name): name is string => Boolean(name)),
  );

  for (let pass = 0; pass <= assignments.length + calls.length; pass++) {
    const before = tainted.size + washed.size;
    let grew = false;

    for (const assignment of assignments) {
      const fromTainted = assignment.from.some((name) => tainted.has(name));
      const fromWashed = assignment.from.some((name) => washed.has(name));
      if (!fromTainted && !fromWashed) continue;

      // Passing through a check moves the value from one set to the other; it
      // stays traceable, but it is no longer the visitor's raw input.
      if (cleaned.has(assignment.target) || fromWashed) washed.add(assignment.target);
      else tainted.add(assignment.target);
    }

    /**
     * `findReportsFor(owner)` taints that function's *first* parameter only.
     *
     * Matching by name alone leaked taint into every function that happened to
     * call a parameter the same thing, which is how a validated route was
     * attributed to an unrelated helper's query.
     */
    for (const call of calls) {
      const fn = functions.find((f) => f.name && f.name === call.callee);
      if (!fn) continue;

      call.args.forEach((argNames, index) => {
        const param = fn.params[index];
        if (!param) return;
        if (argNames.some((name) => tainted.has(name))) {
          if (noteParam(taintedParams, param, fn.name)) grew = true;
        } else if (argNames.some((name) => washed.has(name))) {
          if (noteParam(washedParams, param, fn.name)) grew = true;
        }
      });
    }

    if (tainted.size + washed.size === before && !grew) break;
  }
  return { tainted, washed, taintedParams, washedParams };
}

/**
 * Loose match: a claim will not reproduce an expression character for character.
 *
 * Short names are matched on a word boundary rather than dropped. An earlier
 * version skipped anything under three characters, which silently discarded
 * `id` -- the single most common parameter name there is -- and made every
 * claim about it come back "not found".
 */
function mentions(haystack: string, needle: string): boolean {
  const words = needle
    .replace(/[^A-Za-z0-9_]/g, " ")
    .trim()
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean);

  if (words.length === 0) return false;
  const hay = haystack.toLowerCase();

  return words.some((word) =>
    word.length > 2
      ? hay.includes(word)
      // A boundary, so "id" does not match "video".
      : new RegExp(`\\b${word}\\b`).test(hay)
  );
}

/**
 * Decide one claim.
 *
 * Every rejection says which step failed, so a claim that fails because the
 * verifier could not follow it is distinguishable from one that fails because
 * it was wrong. Those must never be conflated: the first is a gap in this file,
 * the second is a gap in whatever made the claim.
 */
export function verifyClaim(claim: Claim, inventory: Inventory): VerifiedClaim {
  const door = claim.door
    ? inventory.doors.find((d) => d.path === claim.door || d.id.endsWith(`:${claim.door}`))
    : undefined;

  if (claim.door && !door) {
    return { claim, verdict: "not-found", reason: `No route ${claim.door} exists in this code.` };
  }

  /**
   * Sinks worth testing against this claim.
   *
   * Prefer ones inside the named route, but fall back to the rest of the file
   * when it has none. A handler that passes its value to a helper puts the
   * dangerous operation outside its own body -- restricting the search to the
   * handler is exactly what made the enumerating pass miss those, and the point
   * of verifying a claim is to be able to follow it there.
   */
  const ofKind = inventory.sinks.filter((s) => s.kind === claim.sink && !s.inherentlySafe);
  const inDoor = door ? ofKind.filter((s) => s.doorId === door.id) : ofKind;
  const candidateSinks = inDoor.length > 0 ? inDoor : ofKind;

  if (candidateSinks.length === 0) {
    const safeOnes = inventory.sinks.filter((s) => s.kind === claim.sink && s.inherentlySafe);
    return {
      claim,
      ...(door ? { door } : {}),
      verdict: safeOnes.length > 0 ? "blocked" : "not-found",
      reason: safeOnes.length > 0
        ? `The only ${claim.sink} operation there is parameterised, so values cannot alter it.`
        : `No ${claim.sink} operation found${door ? ` on ${door.path}` : ""}.`,
    };
  }

  const candidateSources = inventory.sources.filter((s) => {
    if (door && s.doorId !== door.id) return false;
    if (!claim.parameter) return true;
    return mentions(s.expression, claim.parameter) || mentions(claim.parameter, s.binding ?? "");
  });

  if (candidateSources.length === 0) {
    return {
      claim,
      ...(door ? { door } : {}),
      verdict: "not-found",
      reason: claim.parameter
        ? `No input matching "${claim.parameter}" is read${door ? ` in ${door.path}` : ""}.`
        : "No untrusted input is read there.",
    };
  }

  let bestBlocked: VerifiedClaim | undefined;

  for (const source of candidateSources) {
    const binding = source.binding;
    const sourceAt = positionOf(source.id);
    const path = fileOf(source.id);

    // An inline source with no name cannot be followed by name; it is only
    // reachable if the sink literally contains that expression.
    const flow = binding
      ? taintedNames(binding, sourceAt, path, inventory)
      : {
        tainted: new Set<string>(),
        washed: new Set<string>(),
        taintedParams: new Map<string, Set<string>>(),
        washedParams: new Map<string, Set<string>>(),
      };
    const tainted = flow.tainted;

    const sourceScope = enclosingFunction(inventory, path, sourceAt);

    for (const sink of candidateSinks) {
      /**
       * "The sink must come after the source" holds only inside one function.
       * Across functions it is meaningless -- a helper is often declared above
       * the handler that calls it, and reading order is not execution order.
       * Enforcing it everywhere rejected exactly the cross-function paths this
       * verifier exists to follow.
       */
      const sameScope = sourceScope === enclosingFunction(inventory, fileOf(sink.id), positionOf(sink.id));
      if (sameScope && positionOf(sink.id) <= sourceAt && fileOf(sink.id) === path) continue;

      const sinkFn = enclosingFunctionDef(inventory, fileOf(sink.id), positionOf(sink.id));
      /**
       * A parameter shadows anything of the same name outside the function.
       *
       * So an operand that is a parameter of the function containing the sink
       * can only be reached through the call that bound it -- never by a
       * variable of the same name in the caller. Without this, a value in one
       * route matched an identically-named parameter in every helper, which
       * attributed a finding to the wrong query.
       */
      const carries = (set: Set<string>, scoped: Map<string, Set<string>>): boolean =>
        sink.operands.some((operand) =>
          sinkFn?.params.includes(operand)
            ? (scoped.get(operand)?.has(sinkFn.name) ?? false)
            : set.has(operand)
        );

      const reaches = binding
        ? carries(flow.tainted, flow.taintedParams)
        : mentions(sink.expression, source.expression);

      // Reached, but only by a value that passed a check on the way.
      if (!reaches && binding && carries(flow.washed, flow.washedParams)) {
        bestBlocked ??= {
          claim,
          source,
          sink,
          ...(door ? { door } : {}),
          via: [...tainted, ...flow.washed],
          location: sink.location,
          verdict: "blocked",
          ...(washedBy(inventory, flow) ? { blockedBy: washedBy(inventory, flow)! } : {}),
          reason: "The value is checked before it reaches that operation.",
        };
        continue;
      }
      if (!reaches) continue;

      const blocker = (inventory.sanitizers ?? []).find((sanitizer) => {
        if (fileOf(sanitizer.id) !== path) return false;
        const at = positionOf(sanitizer.id);
        if (at <= sourceAt || at >= positionOf(sink.id)) return false;
        return sanitizer.guards.some((name) => tainted.has(name));
      });

      const common = {
        claim,
        source,
        sink,
        ...(door ? { door } : {}),
        via: [...tainted],
        location: sink.location,
      };

      if (!blocker) {
        return {
          ...common,
          verdict: "valid",
          reason:
            `${source.expression} reaches the ${sink.kind} operation at ` +
            `${sink.location.path}:${sink.location.line} with no check in between.`,
        };
      }
      // Keep looking: another source may reach the same sink unchecked.
      bestBlocked ??= {
        ...common,
        verdict: "blocked",
        blockedBy: blocker,
        reason: `The value is checked by ${blocker.kind} before it is used.`,
      };
    }
  }

  if (bestBlocked) return bestBlocked;

  return {
    claim,
    ...(door ? { door } : {}),
    verdict: "no-path",
    reason: "That input does not reach that operation anywhere this check can follow.",
  };
}

export function verifyAll(claims: Claim[], inventory: Inventory): VerifiedClaim[] {
  return claims.map((claim) => verifyClaim(claim, inventory));
}
