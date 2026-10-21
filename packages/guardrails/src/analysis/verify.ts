import type { CodeLocation } from "../types.ts";
import type {
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

/**
 * "On this route, the value in this input picks a record, and nothing checks
 * the record belongs to whoever is signed in."
 *
 * The kind of claim a model is needed for. Pairing every input with every
 * operation cannot generate it usefully, because whether a record is private
 * -- an invoice, a message -- or meant for everyone -- a product page -- is a
 * judgement about what the application is for. The model makes that judgement;
 * the rules still decide whether the code checks ownership.
 */
export interface OwnershipClaim {
  door: string;
  parameter: string;
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
  claim: Claim | OwnershipClaim;
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

/** Inside the route: its own code, or the named handler it points to. */
function belongsTo(door: Door, entity: { id: string; doorId?: string }): boolean {
  if (entity.doorId === door.id) return true;
  const at = door.handlerAt;
  return Boolean(at) && fileOf(entity.id) === at!.path && within(at!.range, positionOf(entity.id));
}

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
 * Where a value goes, starting from one binding.
 *
 * Names are tracked per scope -- one set for each function the value reaches --
 * because a name means nothing outside its function: two helpers that both
 * call their parameter `owner` hold two different values, and treating them as
 * one attributed a validated route's value to an unrelated helper's query.
 *
 * The search follows the value into every function it is passed to, however
 * many calls deep and across files, until nothing new is learned. Each step is
 * cheap because it starts from one claimed input rather than from every input
 * at once, which is what lets the verifier go where the all-paths pass cannot.
 */
interface ScopeState {
  /** Names still carrying the visitor's value unchecked. */
  tainted: Set<string>;
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

interface Flow {
  /** Per scope: a function's id, or `<file>:top` for code outside any function. */
  byScope: Map<string, ScopeState>;
  /** Every name the value reached, for the audit trail and the blocker check. */
  tainted: Set<string>;
  washed: Set<string>;
  /**
   * Set when the value went somewhere this search could not follow. A claim
   * that fails after this is undecidable, never "no path": the gap is ours.
   */
  unfollowed?: string;
}

const topScope = (path: string) => `${path}:top`;

/** Safety valve on pathological code. Each step is one function revisited. */
const MAX_STEPS = 500;

/**
 * Functions named like this are not ours to follow: language built-ins whose
 * behaviour is known. Passing a value to one is not a gap in the search.
 */
const BUILT_IN = new Set([
  "String", "Number", "Boolean", "parseInt", "parseFloat", "encodeURIComponent",
  "encodeURI", "decodeURIComponent", "decodeURI", "isNaN", "isFinite", "Array",
  "Object", "Symbol", "BigInt", "Date", "RegExp", "Error", "Promise", "structuredClone",
]);

/**
 * `const id = parseInt(req.params.id, 10)` reads the input and checks it in
 * one statement, so the name it lands in already holds the checked value.
 * Starting that name as unchecked reported a number as able to carry query
 * text -- a warning on correct code.
 */
function checkedOnArrival(source: TaintSource, inventory: Inventory): boolean {
  const binding = source.binding;
  return Boolean(binding) && inventory.sanitizers.some(
    (s) =>
      fileOf(s.id) === fileOf(source.id) &&
      s.guards[0] === binding &&
      s.location.line === source.location.line &&
      positionOf(s.id) <= positionOf(source.id),
  );
}

function followValue(
  start: string,
  after: number,
  path: string,
  inventory: Inventory,
  startChecked = false,
): Flow {
  const functions = inventory.functions ?? [];
  const byScope = new Map<string, ScopeState>();
  const state = (key: string): ScopeState => {
    let s = byScope.get(key);
    if (!s) byScope.set(key, (s = { tainted: new Set(), washed: new Set() }));
    return s;
  };

  interface Scope { key: string; fn?: FunctionDef; path: string; after: number }
  const origin = enclosingFunctionDef(inventory, path, after);
  const first: Scope = { key: origin?.id ?? topScope(path), ...(origin ? { fn: origin } : {}), path, after };
  (startChecked ? state(first.key).washed : state(first.key).tainted).add(start);

  const queue: Scope[] = [first];
  const queued = new Set([first.key]);
  let unfollowed: string | undefined;
  let steps = 0;

  while (queue.length > 0) {
    if (++steps > MAX_STEPS) {
      unfollowed ??= "The value travels through more code than this check follows.";
      break;
    }
    const scope = queue.shift()!;
    queued.delete(scope.key);
    const here = state(scope.key);
    const [lo, hi] = scope.fn?.bodyRange ?? [0, Number.POSITIVE_INFINITY];

    /**
     * Only what sits inside this scope and could run after the value arrived.
     *
     * Unscoped, a call in a later route picked up a variable of the same name
     * and carried it into a helper, attributing a finding to a route that
     * never passed that value.
     */
    const inScope = (id: string, file: string) => {
      const at = positionOf(id);
      return file === scope.path && at >= lo && at < hi && at > scope.after;
    };

    const assignments = inventory.assignments.filter((a) => inScope(a.id, fileOf(a.id)));
    const calls = (inventory.calls ?? []).filter((c) => inScope(c.id, c.path));

    /**
     * Names a validation step produces. Taint stops at these.
     *
     * `const owner = Number(raw)` means `owner` is no longer the visitor's
     * value; it is whatever survived the check. Letting taint flow through it
     * reported a route that validates its input as vulnerable -- the worst kind
     * of mistake, because it is a warning about code that is already correct.
     */
    const cleaned = new Set(
      inventory.sanitizers
        .filter((s) => inScope(s.id, fileOf(s.id)))
        .map((s) => s.guards[0])
        .filter((name): name is string => Boolean(name)),
    );

    for (let changed = true; changed;) {
      changed = false;
      for (const assignment of assignments) {
        const fromTainted = assignment.from.some((name) => here.tainted.has(name));
        const fromWashed = assignment.from.some((name) => here.washed.has(name));
        if (!fromTainted && !fromWashed) continue;

        // Passing through a check moves the value from one set to the other;
        // it stays traceable, but it is no longer the visitor's raw input.
        const into = cleaned.has(assignment.target) || !fromTainted ? here.washed : here.tainted;
        if (!into.has(assignment.target)) {
          into.add(assignment.target);
          changed = true;
        }
      }
    }

    /**
     * `findReportsFor(owner)` hands the value to that function's *first*
     * parameter only, and the search continues inside it.
     */
    for (const call of calls) {
      const carried = call.args.map((names) =>
        names.some((n) => here.tainted.has(n)) ? "tainted"
        : names.some((n) => here.washed.has(n)) ? "washed"
        : undefined
      );
      if (!carried.some(Boolean)) continue;

      // Method calls (`c.json(rows)`, `db.query(...)`) are library code. The
      // dangerous ones are recognised as operations in their own right.
      if (call.callee.includes(".")) continue;

      const named = functions.filter((f) => f.name === call.callee);
      const sameFile = named.filter((f) => f.path === scope.path);
      const target = sameFile.length === 1
        ? sameFile[0]
        : sameFile.length === 0 && named.length === 1
        ? named[0]
        : undefined;

      if (!target) {
        if (named.length > 1) {
          unfollowed ??= `The value is passed to ${call.callee}, which is defined in more than one place.`;
        } else if (!BUILT_IN.has(call.callee) && carried.includes("tainted")) {
          unfollowed ??= `The value is passed to ${call.callee}, whose code is not in what was reviewed.`;
        }
        continue;
      }

      const there = state(target.id);
      let learned = false;
      carried.forEach((kind, index) => {
        if (!kind) return;
        const param = target.params[index];
        if (!param) {
          // A destructured or missing parameter: the value goes in, but under
          // no name this search can follow.
          if (kind === "tainted") {
            unfollowed ??= `The value is passed to ${target.name}, which unpacks it in a way this check does not follow.`;
          }
          return;
        }
        const into = kind === "tainted" ? there.tainted : there.washed;
        if (kind === "washed" && there.tainted.has(param)) return;
        if (!into.has(param)) {
          into.add(param);
          learned = true;
        }
      });

      if (learned && !queued.has(target.id)) {
        queue.push({ key: target.id, fn: target, path: target.path, after: -1 });
        queued.add(target.id);
      }
    }
  }

  const tainted = new Set<string>();
  const washed = new Set<string>();
  for (const s of byScope.values()) {
    for (const n of s.tainted) tainted.add(n);
    for (const n of s.washed) washed.add(n);
  }
  return { byScope, tainted, washed, ...(unfollowed ? { unfollowed } : {}) };
}

/**
 * Does the value, as `which` (unchecked or checked), reach any of these names
 * at this position?
 *
 * Looks from the innermost function outward, because code inside a function
 * can read its enclosing function's variables. A parameter stops the search:
 * it shadows anything of the same name further out, so it carries the value
 * only if the value was passed into it. Without that rule a value in one route
 * matched an identically named parameter in every helper.
 */
function reachesOperands(
  flow: Flow,
  which: keyof ScopeState,
  operands: string[],
  file: string,
  position: number,
  inventory: Inventory,
): boolean {
  const chain = (inventory.functions ?? [])
    .filter((fn) => fn.path === file && within(fn.bodyRange, position))
    .sort((a, b) => b.bodyRange[0] - a.bodyRange[0]);

  return operands.some((operand) => {
    for (const fn of chain) {
      const names = flow.byScope.get(fn.id)?.[which];
      if (fn.params.includes(operand)) return names?.has(operand) ?? false;
      if (names?.has(operand)) return true;
    }
    return flow.byScope.get(topScope(file))?.[which].has(operand) ?? false;
  });
}

/**
 * The input is read right inside the operation, as in
 * `db.query("..." + req.body.login + "'")`. Its value never passes through a
 * name, so following names cannot find it; the text can.
 */
function writtenInside(source: TaintSource, sink: Sink): boolean {
  if (fileOf(source.id) !== fileOf(sink.id) || positionOf(source.id) < positionOf(sink.id)) return false;
  // `fetch(url)` is both a reply from elsewhere and a request out. Its reply
  // cannot be inside the request that produces it.
  if (positionOf(source.id) === positionOf(sink.id)) return false;
  const text = source.expression.replace(/\s+/g, " ");
  return text.length > 0 && sink.expression.includes(text);
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
/** Every route a claim's address could mean. A full door id names exactly one. */
function doorsNamed(name: string, inventory: Inventory): Door[] {
  const exact = inventory.doors.filter((d) => d.id === name);
  if (exact.length > 0) return exact;
  return inventory.doors.filter((d) => d.path === name || d.id.endsWith(`:${name}`));
}

const VERDICT_STRENGTH: Record<ClaimVerdict, number> = {
  valid: 0,
  blocked: 1,
  undecidable: 2,
  "no-path": 3,
  "not-found": 4,
};

/**
 * A suggestion often names an address without its method -- "/usersearch" --
 * when a GET shows the form and a POST runs the search. Each route at that
 * address is checked on its own and the most definite answer kept; trying only
 * the first one rejected real problems because the harmless route came first.
 */
function eachDoor(
  claimDoor: string | undefined,
  inventory: Inventory,
  check: (door: string) => VerifiedClaim,
): VerifiedClaim | undefined {
  if (!claimDoor) return undefined;
  // Already pinned to one door id -- even one registered twice -- so stop here.
  if (inventory.doors.some((d) => d.id === claimDoor)) return undefined;
  const doors = doorsNamed(claimDoor, inventory);
  if (doors.length < 2) return undefined;
  return doors
    .map((d) => check(d.id))
    .sort((a, b) => VERDICT_STRENGTH[a.verdict] - VERDICT_STRENGTH[b.verdict])[0];
}

export function verifyClaim(claim: Claim, inventory: Inventory): VerifiedClaim {
  const several = eachDoor(claim.door, inventory, (door) => verifyClaim({ ...claim, door }, inventory));
  if (several) return several;

  const door = claim.door ? doorsNamed(claim.door, inventory)[0] : undefined;

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
  const inDoor = door ? ofKind.filter((s) => belongsTo(door, s)) : ofKind;
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
    if (door && !belongsTo(door, s)) return false;
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
  let unfollowed: string | undefined;

  for (const source of candidateSources) {
    const binding = source.binding;
    const sourceAt = positionOf(source.id);
    const path = fileOf(source.id);

    // An inline source with no name cannot be followed by name; it is only
    // reachable if the sink literally contains that expression.
    const flow: Flow = binding
      ? followValue(binding, sourceAt, path, inventory, checkedOnArrival(source, inventory))
      : { byScope: new Map(), tainted: new Set(), washed: new Set() };
    const tainted = flow.tainted;
    if (flow.unfollowed) unfollowed ??= flow.unfollowed;

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
      if (sameScope && positionOf(sink.id) <= sourceAt && fileOf(sink.id) === path && !writtenInside(source, sink)) {
        continue;
      }

      const carries = (which: keyof ScopeState): boolean =>
        reachesOperands(flow, which, sink.operands, fileOf(sink.id), positionOf(sink.id), inventory);

      // An input read inline has no name to follow; it reaches only the
      // operation it is literally written inside. Matching it by loose words
      // ("req") attributed one route's input to another function's query.
      const reaches = binding
        ? carries("tainted") || writtenInside(source, sink)
        : writtenInside(source, sink);

      // Reached, but only by a value that passed a check on the way.
      if (!reaches && binding && carries("washed")) {
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

  /**
   * The value went somewhere this check could not follow. That is a gap in
   * the check, not evidence of safety, so it must not read as "no path".
   */
  if (unfollowed) {
    return {
      claim,
      ...(door ? { door } : {}),
      verdict: "undecidable",
      reason: `${unfollowed} It may or may not reach that operation.`,
    };
  }

  return {
    claim,
    ...(door ? { door } : {}),
    verdict: "no-path",
    reason: "That input does not reach that operation anywhere this check can follow.",
  };
}

/**
 * Decide an ownership claim.
 *
 * `valid` needs all of: the route exists and requires signing in (one that
 * does not is reported separately); the named input reaches a database query,
 * parameterised or not -- a safe query can still fetch someone else's row; and
 * neither the route nor any function the value passes through asks who is
 * signed in. Asking at all counts as checking. That errs towards silence when
 * the answer is read but never used, which is the side "precision over
 * coverage" picks.
 */
export function verifyOwnership(claim: OwnershipClaim, inventory: Inventory): VerifiedClaim {
  const several = eachDoor(claim.door, inventory, (door) => verifyOwnership({ ...claim, door }, inventory));
  if (several) return several;

  const door = doorsNamed(claim.door, inventory)[0];
  if (!door) {
    return { claim, verdict: "not-found", reason: `No route ${claim.door} exists in this code.` };
  }
  if (door.guards.length === 0) {
    return {
      claim,
      door,
      verdict: "no-path",
      reason: `${door.path} does not require signing in at all; that is reported separately.`,
    };
  }

  // Saved data picks a record only indirectly; ownership is about what the
  // visitor sends now, so stored values are left out (errs to silence).
  const sources = inventory.sources.filter(
    (s) =>
      s.kind !== "stored-data" &&
      belongsTo(door, s) &&
      (mentions(s.expression, claim.parameter) || mentions(claim.parameter, s.binding ?? "")),
  );
  if (sources.length === 0) {
    return { claim, door, verdict: "not-found", reason: `No input matching "${claim.parameter}" is read in ${door.path}.` };
  }

  const lookups = inventory.sinks.filter((s) => s.kind === "sql" || s.kind === "nosql");
  if (lookups.length === 0) {
    return { claim, door, verdict: "not-found", reason: "No database query found." };
  }

  const functions = inventory.functions ?? [];
  let unfollowed: string | undefined;
  let blocked: VerifiedClaim | undefined;

  for (const source of sources) {
    const sourceAt = positionOf(source.id);
    const path = fileOf(source.id);
    const flow: Flow = source.binding
      ? followValue(source.binding, sourceAt, path, inventory, checkedOnArrival(source, inventory))
      : { byScope: new Map(), tainted: new Set(), washed: new Set() };
    if (flow.unfollowed) unfollowed ??= flow.unfollowed;

    // Turning an id into a number does not make it yours, so a checked value
    // still counts here.
    const lookup = lookups.find((sink) => {
      const at = positionOf(sink.id);
      const file = fileOf(sink.id);
      if (
        file === path && at <= sourceAt &&
        enclosingFunction(inventory, file, at) === enclosingFunction(inventory, path, sourceAt) &&
        !writtenInside(source, sink)
      ) {
        return false;
      }
      return source.binding
        ? reachesOperands(flow, "tainted", sink.operands, file, at, inventory) ||
          reachesOperands(flow, "washed", sink.operands, file, at, inventory)
        : belongsTo(door, sink) && writtenInside(source, sink);
    });
    if (!lookup) continue;

    // Everywhere the value went: the route itself and each function it reached.
    const visited = [
      { path: door.location.path, range: door.bodyRange },
      ...[...flow.byScope.keys()].flatMap((key) => {
        const fn = functions.find((f) => f.id === key);
        return fn ? [{ path: fn.path, range: fn.bodyRange }] : [];
      }),
    ];
    const asks = (inventory.identities ?? []).find((who) =>
      !who.displayOnly &&
      visited.some((v) => v.path === who.location.path && within(v.range, positionOf(who.id)))
    );

    const common = {
      claim,
      source,
      sink: lookup,
      door,
      via: [...flow.tainted, ...flow.washed],
      location: lookup.location,
    };

    if (asks) {
      blocked ??= {
        ...common,
        verdict: "blocked",
        reason: `The route checks who is signed in (${asks.expression}) before using the record.`,
      };
      continue;
    }
    return {
      ...common,
      verdict: "valid",
      reason:
        `${source.expression} picks the record looked up at ${lookup.location.path}:${lookup.location.line}, ` +
        `and nothing on the way asks who is signed in.`,
    };
  }

  if (blocked) return blocked;
  if (unfollowed) {
    return { claim, door, verdict: "undecidable", reason: `${unfollowed} It may or may not pick a record.` };
  }
  return { claim, door, verdict: "no-path", reason: "That input does not reach a database query." };
}

export function verifyAll(claims: Claim[], inventory: Inventory): VerifiedClaim[] {
  return claims.map((claim) => verifyClaim(claim, inventory));
}
