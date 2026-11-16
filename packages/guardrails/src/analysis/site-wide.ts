import type { CodeLocation } from "../types.ts";
import {
  dottedName,
  identifiersIn,
  isStringLiteral,
  locationOf,
  walk,
  type Node,
  type ParsedFile,
} from "./ast.ts";
import { bindings as bindingsOf } from "./cleaners.ts";
import type { Door, SignInUnclear, UnclearReason } from "./inventory.ts";

/**
 * Steps registered for a whole app or a section of it -- `app.use(...)`,
 * `router.use(...)`, `app.all("*", ...)`, Hono's `use` -- and whether each
 * one requires signing in for the pages registered after it.
 *
 * Each step gets one of three answers (Murat's plan, 2026-11-15):
 *
 *   check    its code asks who is signed in, turns the visitor away when
 *            nobody is, and lets the request on only past that test; or a
 *            known library check bound to its import; or, only when its code
 *            cannot be read at all, a name that plainly says sign-in.
 *   never    its code never turns anyone away, or does so for another reason
 *            (a rate limit, a size limit, maintenance); session and request
 *            set-up; error handlers; a package with no sign-in word.
 *   unclear  the pages after it go back to the user as "needs your check",
 *            never a pass: addresses let through, a step added only under a
 *            condition, a name handed in, a key or address test, a sign-in
 *            pass looked for but never checked, unreadable code with no
 *            telling name.
 *
 * A step covers only what runs after it: routes registered later on the
 * same app or router, routers mounted after it (`app.use(prefix, router)`,
 * Hono's `app.route`), and files handed the app after it (`routes(app)`),
 * up to three files away.
 */

/** Objects whose method calls register routes and steps. */
export const ROUTER = /^(?:app|router|\w*[Rr]outes?)$/;

/** Names of middleware that is not an access-control check; naming it as a guard would hide a missing one. */
export const NOT_A_GUARD =
  /^(?:cors|secureHeaders|logger|compress|compression|etag|prettyJSON|rateLimiter|rateLimit|limiter|helmet|morgan|bodyParser|json|urlencoded|cookieParser|express|upload|multer|serveStatic|cache|validate\w*)$/;

/**
 * Middleware that gives every visitor a session, or prepares sign-in,
 * without requiring anyone to be signed in: `session({...})`,
 * `cookieSession(...)`, `passport.initialize()`, `passport.session()`,
 * flash messages. Registered site-wide, these used to count as a sign-in
 * check on every route, so an Express app with sessions and no check at all
 * got no open-page warning (known gap, 2026-10-23). Matched on the exact
 * call, so `passport.authenticate(...)` and `requireSession` still count.
 */
const SESSION_SETUP = /^(?:session|cookieSession|expressSession|passport\.(?:initialize|session)|flash)$/;

/** Packages that prepare a request or a session and require nothing of the visitor. */
const SETUP_PACKAGE =
  /^(?:express-session|cookie-session|express-flash|connect-flash|cookie-parser|body-parser|morgan|cors|helmet|compression|serve-favicon|express-fileupload|multer|method-override)$/;

/**
 * The names that may be a sign-in check in one argument of `app.use(...)`.
 * For a call such as `session({ secret, store })` or `cors({ origin })` only
 * what is called counts, never the settings passed to it: a setting named
 * `allowedOrigins` is not a check. These are also the names a counted step
 * adds to a route's guards.
 */
export function guardNamesIn(arg: Node): string[] {
  // `app.use(require("express-flash")())`: a package known to set things up
  // is not a check. Any other `require(...)` may well be the app's own check.
  const required = requiredModule(arg);
  if (required !== undefined) return SETUP_PACKAGE.test(required) ? [] : ["require"];
  if (arg.type === "CallExpression") {
    const called = dottedName(arg.callee);
    // `dottedName` of a call ends in "()": only a plain `a.b(...)` is read this way.
    if (called && !called.includes("(")) {
      return SESSION_SETUP.test(called) ? [] : identifiersIn(arg.callee as Node);
    }
  }
  return identifiersIn(arg);
}

/**
 * The module named by the `require("...")` an expression is built on
 * (`require("x")`, `require("x")()`, `require("x").y`, `require("x").y()`),
 * or undefined when it is not built on one.
 */
function requiredModule(node: Node): string | undefined {
  let current: Node | undefined = node;
  for (let depth = 0; current && depth < 6; depth++) {
    if (current.type === "CallExpression") {
      const callee = current.callee as Node | undefined;
      const args = (current.arguments ?? []) as Node[];
      if (callee?.type === "Identifier" && callee.name === "require") {
        return args.length === 1 && isStringLiteral(args[0]) ? String(args[0].value) : undefined;
      }
      current = callee;
    } else if (current.type.endsWith("MemberExpression")) {
      current = current.object as Node | undefined;
    } else {
      return undefined;
    }
  }
  return undefined;
}

/**
 * The names this file binds to passport itself: its default or whole-module
 * import (`import passport from "passport"`, `require("passport")`), and an
 * instance made from its `Passport` class (`const p = new Passport()`). Each
 * must be bound exactly once in the file and never written.
 */
export function passportNames(parsed: ParsedFile): Set<string> {
  const names = new Set<string>();
  const classes = new Set<string>();
  const once = (name: string) => {
    const b = bindingsOf(parsed.program, name);
    return b.declared === 1 && b.written === 0;
  };
  const isPassport = (node: Node | undefined) => isStringLiteral(node) && node.value === "passport";
  walk(parsed.program, (node) => {
    if (node.type === "ImportDeclaration" && isPassport(node.source as Node) && node.importKind !== "type") {
      for (const specifier of (node.specifiers ?? []) as Node[]) {
        const local = String((specifier.local as Node | undefined)?.name ?? "");
        if (specifier.type === "ImportDefaultSpecifier" || specifier.type === "ImportNamespaceSpecifier") names.add(local);
        if (specifier.type === "ImportSpecifier" && (specifier.imported as Node | undefined)?.name === "Passport" && specifier.importKind !== "type") classes.add(local);
      }
    }
    if (node.type === "VariableDeclarator" && (node.id as Node | undefined)?.type === "Identifier") {
      const init = node.init as Node | undefined;
      const required = init?.type === "CallExpression" && dottedName(init.callee) === "require" && isPassport(((init.arguments ?? []) as Node[])[0]);
      if (required) names.add(String((node.id as Node).name));
    }
  });
  // Instances, once the class names are known.
  walk(parsed.program, (node) => {
    if (node.type !== "VariableDeclarator" || (node.id as Node | undefined)?.type !== "Identifier") return;
    const init = node.init as Node | undefined;
    const made = init?.type === "NewExpression" ? dottedName(init.callee) : undefined;
    if (made && (classes.has(made) || [...names].some((n) => made === `${n}.Passport`))) names.add(String((node.id as Node).name));
  });
  for (const name of names) if (!once(name)) names.delete(name);
  for (const name of classes) if (!once(name)) for (const n of names) names.delete(n);
  return names;
}

// --- where a route sits -------------------------------------------------------

/** For each door: the object its route was registered on, and where. Set by `findDoors`. */
export const routeSeen = new WeakMap<Door, { object: string; scope: number; at: number; fn: number }>();

/**
 * The function a call sits in (its start), or -1 at the top of the file.
 * Steps and routes are ordered by position only within one function: a
 * step added inside another function runs whenever, and if, that one is
 * called.
 */
export function enclosingFunction(parents: Node[]): number {
  return parents.find((p) => FUNCTION.test(p.type))?.start ?? -1;
}

const FUNCTION = /^(?:ArrowFunctionExpression|FunctionExpression|FunctionDeclaration)$/;

/** Each declarator directly in `fn`'s body, nested functions left out. */
function declaresDirectly(fn: Node, name: string): boolean {
  let found = false;
  const body = fn.body as Node | undefined;
  if (!body) return false;
  const visit = (node: Node): void => {
    if (found) return;
    if (node !== body && FUNCTION.test(node.type)) {
      if (node.type === "FunctionDeclaration" && (node.id as Node | undefined)?.name === name) found = true;
      return;
    }
    if (node.type === "VariableDeclarator" && identifiersIn(node.id as Node).includes(name)) found = true;
    for (const key of Object.keys(node)) {
      if (key === "type" || key === "start" || key === "end") continue;
      const value = node[key];
      if (Array.isArray(value)) for (const item of value) { if (item && typeof item === "object" && typeof (item as Node).type === "string") visit(item as Node); }
      else if (value && typeof value === "object" && typeof (value as Node).type === "string") visit(value as Node);
    }
  };
  visit(body);
  return found;
}

/**
 * The function that binds `name` at a point, from the innermost out: as a
 * parameter, or declared directly in its body. -1 when the file itself
 * binds it (or nothing does). Two `app`s in different functions are two
 * objects.
 */
export function scopeOf(name: string, parents: Node[]): number {
  if (!/^[A-Za-z_$][\w$]*$/.test(name)) return -1;
  for (const parent of parents) {
    if (!FUNCTION.test(parent.type)) continue;
    const params = (parent.params ?? []) as Node[];
    if (params.some((p) => identifiersIn(p).includes(name))) return parent.start;
    if (declaresDirectly(parent, name)) return parent.start;
  }
  return -1;
}

// --- answers --------------------------------------------------------------------

type Answer =
  | { kind: "check"; names: string[] }
  | { kind: "never" }
  | { kind: "unclear"; reason: UnclearReason };

const NEVER: Answer = { kind: "never" };
const unclear = (reason: UnclearReason): Answer => ({ kind: "unclear", reason });

/**
 * A name that plainly says it checks signing in. A role word alone
 * (`adminLogger`, `adminHandler`) does not; one next to a check word does
 * (`isAdmin`, `adminOnly`, `checkRole`, `requireAdmin`). Trusted only when the
 * step's code cannot be read at all (Murat's decision, 2026-11-15): a
 * readable body always decides instead. Case-sensitive where a word starts
 * a camel-case part, so `requirements` and `authors` do not count while
 * `requireUser` does.
 */
const SIGN_IN_NAME =
  /[Aa]uth(?!ors?\b|or[A-Z_]|ored\b)|[Ll]og(?:ged)?[Ii]n|login|[Ss]igned|[Ss]ign[Ii]n|[Gg]uard|[Pp]rotect|require[A-Z_]|requires[A-Z]|ensure[A-Z_]|verify(?:Token|Jwt|JWT|User|Session|Auth)|[Jj]wt|JWT|[Dd]eny|(?:is|only|check|has|ensure|must[Bb]e)(?:Admin|Role|Permission|Staff)|[Aa]dmin(?:Only|Guard|Required)|[Rr]ole(?:Guard|Required)/;

/**
 * A package (or the module path of an unread file) whose name says sign-in.
 * Role words alone (`@/routes/admin`, `firebase-admin`) do not: they name
 * what is behind a check as often as the check itself.
 */
const PACKAGE_SAYS =
  /auth(?!ors?(?:\b|[-_/]))|login|logged|signin|sign-in|guard|protect|jwt|passport|keycloak|oauth|oidc|openid|bearer/i;
/** Names that are only a role word, read as what a check protects rather than a check. */
const ROLE_WORD_ONLY = /^(?:admin|admins|role|roles|permission|permissions|acl)$/i;
/**
 * Words that say a step lets visitors through, wants them signed out, or
 * does another job (`optionalAuth`, `noAuth`, `checkNotAuthenticated`,
 * `forwardAuthenticated`, `authLogger`, `loginLimiter`, `authCors`): never
 * trusted by name, whatever else the name says.
 */
const SAYS_OTHERWISE = /[Oo]ptional|^no[A-Z_]|[Nn]one|[Aa]nonymous|[Gg]uest|[Ee]xcept|[Pp]ublic|[Ll]ogger|[Ll]ogging|[Ll]ogs\b|^(?:set|attach|load|add|init|skip|bypass|maybe|soft|try|lenient|lazy|passive)[A-Z_]|[Ss]kip|[Bb]ypass|IfPresent|[Dd]ecode|^initiali[sz]e$|Handler$|^to[A-Z]\w*Handler$|[Nn]ot[A-Z]|[Ll]ogged[Oo]ut|[Uu]nauth|^(?:redirect|forward)[A-Z]|[Ll]imit|[Cc]ors\b|Cors|[Cc]srf|Csrf|Parser$|Https$|Json$|Body$|Trace$|Context$|RequestId$|Status$/;

/** Wrappers that run a step and pass its errors on, changing nothing else. */
const ASYNC_WRAPPER = /^(?:asyncHandler|expressAsyncHandler|catchAsync|wrapAsync|asyncWrap|asyncMiddleware)$/;

/** Names of routers and route modules: what a check covers, never a check. */
const ROUTER_NAME = /(?:[Rr]outer|[Rr]outes?|[Cc]ontroller)$/;

/** Library checks, by package and export, bound to their import. */
const KNOWN_CHECKS: Record<string, { checks: RegExp; never?: RegExp; optional?: RegExp }> = {
  "express-jwt": { checks: /^(?:default|expressjwt|jwt)$/, optional: /\bcredentialsRequired\s*:\s*false\b/ },
  "connect-ensure-login": { checks: /^(?:ensureLoggedIn|ensureAuthenticated)$/, never: /^(?:ensureLoggedOut|ensureNotAuthenticated)$/ },
  "express-openid-connect": { checks: /^(?:requiresAuth|auth)$/, optional: /\bauthRequired\s*:\s*false\b/ },
  "express-oauth2-jwt-bearer": { checks: /^(?:auth|requiredScopes)$/, optional: /\bauthRequired\s*:\s*false\b/ },
  // Clerk's other packages only record who is signed in, except the Express SDK's `ClerkExpressRequireAuth`.
  "@clerk/express": { checks: /^requireAuth$/, never: /^clerkMiddleware$/ },
  "@clerk/clerk-sdk-node": { checks: /^ClerkExpressRequireAuth$/, never: /^ClerkExpressWithAuth$/ },
  "@hono/clerk-auth": { checks: /^$/, never: /^clerkMiddleware$/ },
  "@clerk/nextjs": { checks: /^$/, never: /^(?:clerkMiddleware|authMiddleware)$/ },
  "@clerk/nextjs/server": { checks: /^$/, never: /^(?:clerkMiddleware|authMiddleware)$/ },
  // The sign-in pages themselves, mounted for every address: they refuse nobody.
  "better-auth/node": { checks: /^$/, never: /^toNodeHandler$/ },
  "@auth/express": { checks: /^$/, never: /^ExpressAuth$/ },
  "next-auth": { checks: /^$/, never: /./ },
  // They read a sign-in pass and refuse nobody.
  "express-bearer-token": { checks: /^$/, never: /./ },
  "jwt-decode": { checks: /^$/, never: /./ },
  "hono/jwt": { checks: /^jwt$/ },
  "hono/bearer-auth": { checks: /^bearerAuth$/ },
  "hono/basic-auth": { checks: /^basicAuth$/ },
  "express-basic-auth": { checks: /^default$/ },
  passport: { checks: /^(?:authenticate|authorize)$/, never: /^(?:initialize|session)$/, optional: /^\s*\(\s*["'](?:anonymous|session)["']/ },
};

/** Packages whose steps test a key or the visitor's network address, not a person. */
const KEY_OR_ADDRESS_PACKAGE = /^(?:express-ipfilter|express-ip-access-control|ip-filter|express-api-key-auth)$/;

/**
 * `options` is the call's text after its name, `("jwt", { session: false })`,
 * or "" when not called; `readable` is false when its settings are held in
 * a name or spread in, so a setting that lets everyone through could be
 * there unseen.
 */
function packageAnswer(spec: string, member: string, options: string, readable: boolean, names: string[]): Answer {
  const known = KNOWN_CHECKS[spec];
  if (known) {
    if (known.never?.test(member)) return NEVER;
    if (known.checks.test(member)) {
      if (known.optional && !readable) return unclear("optional");
      return known.optional?.test(options) ? unclear("optional") : { kind: "check", names };
    }
  }
  if (KEY_OR_ADDRESS_PACKAGE.test(spec)) return unclear("key-or-address");
  // A known package's other exports: not a check this list knows of.
  if (known || spec.startsWith("@clerk/")) return /^(?:require|protect)/i.test(member) ? unclear("unreadable") : NEVER;
  if (SETUP_PACKAGE.test(spec) || spec === "express" || spec.startsWith("hono/")) return NEVER;
  if (SAYS_OTHERWISE.test(member)) return unclear("unreadable");
  if (SIGN_IN_NAME.test(member) && !ROLE_WORD_ONLY.test(member)) return { kind: "check", names };
  // A package named for sign-in: its main export counts by that name
  // (Murat's decision); any other export of it says nothing either way.
  if (PACKAGE_SAYS.test(spec)) return member === "default" ? { kind: "check", names } : unclear("unreadable");
  return NEVER;
}

// --- files and values ---------------------------------------------------------

interface FileInfo {
  parsed: ParsedFile;
  path: string;
  /** Which of Express and Hono the file loads (`Project.loads`). */
  loads?: { express: boolean; hono: boolean };
  /** Each `require`/import of this file's: local name -> what it names. */
  passport?: Set<string>;
}

type Resolved =
  | { kind: "function"; fn: Node; file: FileInfo }
  | { kind: "package"; spec: string; member: string }
  | { kind: "module"; file: FileInfo }
  | { kind: "call"; call: Node; file: FileInfo }
  | { kind: "unclear"; reason: UnclearReason }
  | { kind: "unknown" };

const MAX_HOPS = 3;

/** The app's own files, also through a path alias (`@/routes/admin`, `~/lib`, `#auth`), as opposed to a package. */
const isLocalSpec = (spec: string): boolean => /^(?:\.|\/|@\/|~\/|#)/.test(spec);

function unwrap(node: Node | undefined): Node | undefined {
  let current = node;
  while (current && /^(?:TSAsExpression|TSSatisfiesExpression|TSNonNullExpression|TSTypeAssertion|ParenthesizedExpression|AwaitExpression|ChainExpression)$/.test(current.type)) {
    current = (current.expression ?? current.argument) as Node | undefined;
  }
  return current;
}

const isFunction = (node: Node | undefined): boolean =>
  node !== undefined && /^(?:ArrowFunctionExpression|FunctionExpression)$/.test(node.type);

/** The site-wide pass over the whole project. */
class Project {
  private readonly files = new Map<string, FileInfo>();

  constructor(parsedFiles: ParsedFile[]) {
    for (const parsed of parsedFiles) this.files.set(parsed.path, { parsed, path: parsed.path });
  }

  all(): FileInfo[] {
    return [...this.files.values()];
  }

  fileAt(path: string): FileInfo | undefined {
    return this.files.get(path);
  }

  /** `./routes/api` from `server/app.js`, tried with the usual endings. */
  resolveModule(from: FileInfo, spec: string): FileInfo | undefined {
    if (!spec.startsWith(".") && !spec.startsWith("/")) return undefined;
    const base = from.path.split("/").slice(0, -1);
    const parts = spec.startsWith("/") ? [] : base;
    for (const piece of spec.split("/")) {
      if (piece === "" || piece === ".") continue;
      if (piece === "..") parts.pop();
      else parts.push(piece);
    }
    const joined = parts.join("/");
    const stem = joined.replace(/\.(?:[cm]?js|jsx)$/, "");
    const candidates = [joined, ...["ts", "tsx", "js", "jsx", "mjs", "cjs", "mts", "cts"].flatMap((ext) => [`${stem}.${ext}`, `${joined}/index.${ext}`])];
    for (const candidate of candidates) {
      const found = this.files.get(candidate);
      if (found) return found;
    }
    return undefined;
  }

  /** Which of Express and Hono a file imports or requires, read from its code, not its text. */
  loads(file: FileInfo): { express: boolean; hono: boolean } {
    if (file.loads) return file.loads;
    const loads = { express: false, hono: false };
    const see = (spec: string) => {
      if (spec === "express") loads.express = true;
      if (spec === "hono" || spec.startsWith("hono/") || spec.startsWith("@hono/")) loads.hono = true;
    };
    walk(file.parsed.program, (node) => {
      if (node.type === "ImportDeclaration") see(String((node.source as Node).value ?? ""));
      const required = node.type === "CallExpression" && dottedName(node.callee) === "require" ? ((node.arguments ?? []) as Node[])[0] : undefined;
      if (isStringLiteral(required)) see(String(required.value));
    });
    file.loads = loads;
    return loads;
  }

  passportIn(file: FileInfo): Set<string> {
    file.passport ??= passportNames(file.parsed);
    return file.passport;
  }

  /**
   * What a name stands for in a file. A name bound more than once, or
   * written after it is bound, cannot be told apart, so it is unclear; one
   * bound nowhere is out of sight.
   */
  resolveName(name: string, file: FileInfo, hops: number): Resolved {
    const bound = bindingsOf(file.parsed.program, name);
    if (bound.declared === 0) return { kind: "unknown" };
    if (bound.declared > 1 || bound.written > 0) return { kind: "unclear", reason: "parameter" };
    let found: Resolved | undefined;
    walk(file.parsed.program, (node) => {
      if (found) return;
      if (node.type === "FunctionDeclaration" && (node.id as Node | undefined)?.name === name) {
        found = { kind: "function", fn: node, file };
      } else if (FUNCTION.test(node.type) && ((node.params ?? []) as Node[]).some((p) => identifiersIn(p).includes(name))) {
        found = { kind: "unclear", reason: "parameter" };
      } else if (node.type === "VariableDeclarator") {
        const id = node.id as Node;
        if (id.type === "Identifier" && id.name === name) {
          found = node.init ? this.resolveValue(node.init as Node, file, hops) : { kind: "unknown" };
        } else if (identifiersIn(id).includes(name)) {
          // `const { requireLogin } = require("./auth")`
          const init = unwrap(node.init as Node | undefined);
          const property = ((id.properties ?? []) as Node[]).find((p) => (p.value as Node | undefined)?.type === "Identifier" && (p.value as Node).name === name);
          const key = property ? ((property.key as Node | undefined)?.name as string | undefined) : undefined;
          found = init && key ? this.member(this.resolveValue(init, file, hops), key, hops) : { kind: "unknown" };
        }
      } else if (node.type === "ImportDeclaration") {
        const spec = String((node.source as Node).value ?? "");
        for (const specifier of (node.specifiers ?? []) as Node[]) {
          if ((specifier.local as Node | undefined)?.name !== name) continue;
          const local = this.resolveModule(file, spec);
          const imported = specifier.type === "ImportDefaultSpecifier"
            ? "default"
            : specifier.type === "ImportNamespaceSpecifier"
              ? "*"
              : String((specifier.imported as Node | undefined)?.name ?? (specifier.imported as Node | undefined)?.value ?? "");
          if (!local) {
            found = isLocalSpec(spec) ? { kind: "unknown" } : { kind: "package", spec, member: imported === "*" ? "default" : imported };
          } else {
            found = imported === "*" ? { kind: "module", file: local } : this.exported(local, imported, hops + 1);
          }
        }
      } else if (node.type === "CatchClause" && node.param && identifiersIn(node.param as Node).includes(name)) {
        found = { kind: "unknown" };
      }
    });
    return found ?? { kind: "unknown" };
  }

  /** What an expression stands for, following names, requires and exports. */
  resolveValue(raw: Node, file: FileInfo, hops: number): Resolved {
    if (hops > MAX_HOPS) return { kind: "unknown" };
    const node = unwrap(raw);
    if (!node) return { kind: "unknown" };
    if (isFunction(node) || node.type === "FunctionDeclaration") return { kind: "function", fn: node, file };
    if (node.type === "Identifier") return this.resolveName(String(node.name), file, hops);
    if (node.type === "CallExpression") {
      const callee = unwrap(node.callee as Node);
      const args = (node.arguments ?? []) as Node[];
      if (callee?.type === "Identifier" && callee.name === "require" && args.length === 1 && isStringLiteral(args[0])) {
        const spec = String(args[0].value);
        const local = this.resolveModule(file, spec);
        if (local) return { kind: "module", file: local };
        return isLocalSpec(spec) ? { kind: "unknown" } : { kind: "package", spec, member: "default" };
      }
      return { kind: "call", call: node, file };
    }
    if (node.type.endsWith("MemberExpression") && !node.computed) {
      const property = String((node.property as Node | undefined)?.name ?? "");
      return this.member(this.resolveValue(node.object as Node, file, hops), property, hops);
    }
    return { kind: "unknown" };
  }

  private member(of: Resolved, property: string, hops: number): Resolved {
    if (of.kind === "module") return this.exported(of.file, property, hops + 1);
    if (of.kind === "package") return { kind: "package", spec: of.spec, member: of.member === "default" ? property : `${of.member}.${property}` };
    if (of.kind === "unclear") return of;
    return { kind: "unknown" };
  }

  /**
   * What a file hands out under `name` ("default" for `module.exports =` or
   * `export default`): read from its top-level statements only. Handed out
   * twice is unclear.
   */
  exportedNodes(file: FileInfo, name: string): Node[] {
    const values: Node[] = [];
    const take = (value: Node | undefined) => { if (value) values.push(value); };
    for (const statement of (file.parsed.program.body ?? []) as Node[]) {
      if (statement.type === "ExpressionStatement") {
        const expression = statement.expression as Node;
        if (expression.type !== "AssignmentExpression") continue;
        const left = dottedName(expression.left) ?? "";
        const right = expression.right as Node;
        if (left === "module.exports") {
          if (name === "default") take(right);
          const object = unwrap(right);
          if (object?.type === "ObjectExpression") {
            for (const prop of (object.properties ?? []) as Node[]) {
              const key = (prop.key as Node | undefined)?.name ?? (prop.key as Node | undefined)?.value;
              if (key === name && !prop.computed) take(prop.value as Node);
            }
          }
        } else if (left === `module.exports.${name}` || left === `exports.${name}`) {
          take(right);
        }
      } else if (statement.type === "ExportDefaultDeclaration" && name === "default") {
        take(statement.declaration as Node);
      } else if (statement.type === "ExportNamedDeclaration" && !statement.source) {
        const declaration = statement.declaration as Node | undefined;
        if (declaration?.type === "FunctionDeclaration" && (declaration.id as Node | undefined)?.name === name) take(declaration);
        if (declaration?.type === "VariableDeclaration") {
          for (const d of (declaration.declarations ?? []) as Node[]) {
            if ((d.id as Node).type === "Identifier" && (d.id as Node).name === name) take(d.init as Node);
          }
        }
        for (const specifier of (statement.specifiers ?? []) as Node[]) {
          const exportedName = (specifier.exported as Node | undefined)?.name ?? (specifier.exported as Node | undefined)?.value;
          if (exportedName === name) take(specifier.local as Node);
        }
      }
    }
    return values;
  }

  exported(file: FileInfo, name: string, hops: number): Resolved {
    if (hops > MAX_HOPS) return { kind: "unknown" };
    const values = this.exportedNodes(file, name);
    if (values.length > 1) return { kind: "unclear", reason: "parameter" };
    if (values.length === 0) return name === "default" ? { kind: "module", file } : { kind: "unknown" };
    return this.resolveValue(values[0]!, file, hops);
  }

  // --- classifying one step -----------------------------------------------------

  /**
   * The answer for one argument of `app.use(...)`. `conditional` when the
   * argument itself chooses the step (`on ? requireAuth : skip`, `on && requireAuth`).
   */
  classifyStep(arg: Node, file: FileInfo): { answer: Answer; label: string; conditional?: boolean } {
    const inner = unwrap(arg);
    if (inner?.type === "SpreadElement") return { answer: unclear("unreadable"), label: "" };
    if (inner?.type === "ConditionalExpression" || inner?.type === "LogicalExpression") {
      const branches = inner.type === "ConditionalExpression" ? [inner.consequent as Node, inner.alternate as Node] : [inner.left as Node, inner.right as Node];
      const answers = branches.map((b) => this.classifyStep(b, file));
      const label = answers.map((a) => a.label).filter(Boolean).join(" or ");
      const check = answers.find((a) => a.answer.kind === "check");
      if (check) return { answer: check.answer, label, conditional: true };
      const doubt = answers.find((a) => a.answer.kind === "unclear");
      return { answer: doubt ? doubt.answer : NEVER, label };
    }
    const legacy = guardNamesIn(arg).filter((n) => !NOT_A_GUARD.test(n));
    const required = requiredModule(arg);
    const label = isFunction(unwrap(arg))
      ? ""
      : required ?? dottedName(arg.type === "CallExpression" ? arg.callee : arg)?.replace(/\(\)/g, "") ?? legacy.join(".");
    // Session set-up and the plain request steps (`cors()`, `express.json()`).
    if (legacy.length === 0) return { answer: NEVER, label };
    // Written inline, it is named by what it tests (`req.session.userId`), not its parameters.
    return { answer: this.classifyValue(arg, file, 0, label, label === "" ? [] : legacy), label };
  }

  private byName(label: string, names: string[]): Answer {
    // `adminRouter`, `require("./routes/admin")`: a router out of sight, not a check.
    const last = label.split(/[./]/).filter(Boolean).pop() ?? "";
    if (ROUTER_NAME.test(last) || /(?:^|\/)routes?\//.test(label) || SAYS_OTHERWISE.test(last)) return unclear("unreadable");
    // A module path (`./middleware/auth`, `connect-ensure-login`) is read like a package name.
    const says = /[/-]/.test(label) ? PACKAGE_SAYS.test(label) : SIGN_IN_NAME.test(label) && !ROLE_WORD_ONLY.test(last);
    return says ? { kind: "check", names } : unclear("unreadable");
  }

  private classifyValue(raw: Node, file: FileInfo, hops: number, label: string, names: string[]): Answer {
    const node = unwrap(raw);
    if (!node) return unclear("unreadable");
    if (isFunction(node)) return this.readMiddleware(node, file, hops, names);
    // `require("./middleware/gate")` is the module's value, not a factory call.
    const requiresDirectly = node.type === "CallExpression" && (node.callee as Node).type === "Identifier" && (node.callee as Node).name === "require";
    if (node.type === "CallExpression" && !requiresDirectly) return this.classifyCall(node, file, hops, label, names);
    return this.classifyResolved(this.resolveValue(node, file, hops), hops, label, names, false);
  }

  private classifyResolved(resolved: Resolved, hops: number, label: string, names: string[], asFactory: boolean): Answer {
    switch (resolved.kind) {
      case "function":
        return asFactory ? this.readFactory(resolved.fn, resolved.file, hops, label, names) : this.readMiddleware(resolved.fn, resolved.file, hops, names);
      case "package":
        return packageAnswer(resolved.spec, resolved.member, "", true, names);
      case "module": {
        const inner = this.exported(resolved.file, "default", hops + 1);
        if (inner.kind === "module") return this.byName(label, names);
        return this.classifyResolved(inner, hops + 1, label, names, asFactory);
      }
      case "call":
        return asFactory ? this.byName(label, names) : this.classifyCall(resolved.call, resolved.file, hops, label, names);
      case "unclear":
        return unclear(resolved.reason);
      case "unknown":
        return this.byName(label, names);
    }
  }

  /** A call in a step's place: a library check, or the app's own factory (`onlyMembers()`). */
  private classifyCall(call: Node, file: FileInfo, hops: number, label: string, names: string[]): Answer {
    if (hops > MAX_HOPS) return this.byName(label, names);
    const callee = unwrap(call.callee as Node);
    if (!callee) return this.byName(label, names);
    const called = dottedName(callee) ?? "";
    if (SESSION_SETUP.test(called)) return NEVER;
    const args = (call.arguments ?? []) as Node[];
    const method = callee.type.endsWith("MemberExpression") && !callee.computed ? String((callee.property as Node | undefined)?.name ?? "") : "";
    // `requireLogin.bind(this)`: the same function, read for what it does.
    if (method === "bind") return this.classifyValue(callee.object as Node, file, hops, label.replace(/\.bind$/, ""), names);
    // `asyncHandler(check)`: a wrapper that only passes errors on; the step is its argument.
    if (args.length === 1 && ASYNC_WRAPPER.test(called.split(".").pop() ?? "")) {
      const inner = this.classifyStep(args[0]!, file);
      return inner.conditional && inner.answer.kind === "check" ? unclear("conditional") : inner.answer;
    }
    // `expressjwt({...}).unless({ path: ["/orders"] })`: some addresses skip the check.
    if (callee.type.endsWith("MemberExpression") && /^(?:unless|except|excluding)$/.test(String((callee.property as Node | undefined)?.name ?? ""))) {
      return unclear("exempt");
    }
    // `passport.authenticate("jwt")`, with passport bound to its import.
    if (callee.type.endsWith("MemberExpression") && !callee.computed) {
      const object = callee.object as Node;
      const method = String((callee.property as Node | undefined)?.name ?? "");
      if (object.type === "Identifier" && this.passportIn(file).has(String(object.name))) {
        return packageAnswer("passport", method, argumentsText(call, file), readableOptions(call, true), names);
      }
    }
    const resolved = this.resolveValue(callee, file, hops);
    if (resolved.kind === "package") return packageAnswer(resolved.spec, resolved.member, argumentsText(call, file), readableOptions(call, resolved.spec === "passport"), names);
    if (resolved.kind === "call") {
      // `require("./guard")()` or `makeGuard(options)()`: the inner call made the factory.
      const inner = this.resolveValue(resolved.call, resolved.file, hops);
      return inner.kind === "call" ? this.byName(label, names) : this.classifyResolved(inner, hops + 1, label, names, true);
    }
    return this.classifyResolved(resolved, hops, label, names, true);
  }

  /** A function called to make a step: what it returns is the step. */
  private readFactory(fn: Node, file: FileInfo, hops: number, label: string, names: string[]): Answer {
    const body = fn.body as Node | undefined;
    let returned: Node | undefined;
    if (body && body.type !== "BlockStatement") returned = body;
    else if (body) {
      const returns: Node[] = [];
      const visit = (node: Node): void => {
        if (node !== body && FUNCTION.test(node.type)) return;
        if (node.type === "ReturnStatement" && node.argument) returns.push(node.argument as Node);
        for (const key of Object.keys(node)) {
          if (key === "type" || key === "start" || key === "end") continue;
          const value = node[key];
          if (Array.isArray(value)) for (const item of value) { if (item && typeof item === "object" && typeof (item as Node).type === "string") visit(item as Node); }
          else if (value && typeof value === "object" && typeof (value as Node).type === "string") visit(value as Node);
        }
      };
      visit(body);
      if (returns.length === 0) return unclear("unreadable");
      // Several things it may return (`if (off) return skip; return check;`):
      // a check only when every one of them is.
      if (returns.length > 1) {
        const answers = returns.map((r) => this.readReturned(r, fn, file, hops, label, names));
        if (answers.every((a) => a.kind === "check")) return answers[0]!;
        if (answers.every((a) => a.kind === "never")) return NEVER;
        return answers.find((a) => a.kind === "unclear") ?? unclear("optional");
      }
      returned = returns[0];
    }
    return this.readReturned(returned, fn, file, hops, label, names);
  }

  /** One value a factory returns, read as the step it makes. */
  private readReturned(returned: Node | undefined, fn: Node, file: FileInfo, hops: number, label: string, names: string[]): Answer {
    const body = fn.body as Node | undefined;
    const value = unwrap(returned);
    if (!value) return unclear("unreadable");
    if (isFunction(value)) return this.readMiddleware(value, file, hops, names);
    if (value.type === "CallExpression") return this.classifyCall(value, file, hops + 1, label, names);
    if (value.type === "Identifier" && body?.type === "BlockStatement") {
      // `function guard() { function check(req, res, next) {...} return check; }`
      let inner: Node | undefined;
      walk(body, (n) => {
        if (n.type === "FunctionDeclaration" && (n.id as Node | undefined)?.name === value.name) inner = n;
        if (n.type === "VariableDeclarator" && (n.id as Node).type === "Identifier" && (n.id as Node).name === value.name && isFunction(unwrap(n.init as Node))) inner = unwrap(n.init as Node);
      });
      if (inner) return this.readMiddleware(inner, file, hops, names);
    }
    return this.classifyValue(value, file, hops + 1, label, names);
  }

  /**
   * Reads a middleware function: does every way on to the next step pass a
   * test of who is signed in?
   */
  private readMiddleware(fn: Node, file: FileInfo, hops: number, names: string[]): Answer {
    const params = (fn.params ?? []) as Node[];
    // Four parameters: an error handler, which only runs when something failed.
    if (params.length >= 4) return NEVER;
    const paramName = (p: Node | undefined) => (p?.type === "Identifier" ? String(p.name) : "");
    let next: string | undefined;
    if (params.length === 3) next = paramName(params[2]);
    else if (params.length === 2 && calls(fn, paramName(params[1]))) next = paramName(params[1]);
    // It answers every request itself; it runs nothing after it.
    if (next === undefined) return NEVER;
    if (next === "") return unclear("unreadable");
    const reading = new Reading(fn, params.length === 3 ? paramName(params[0]) : "", paramName(params[0]), next, (call) => this.throwsOnBadPass(call, file));
    return reading.answer(names, (call) => this.delegate(call, file, hops));
  }

  /**
   * True for a library check that throws (or rejects) when a sign-in pass is
   * not genuine, bound to its import: jsonwebtoken's `verify`, jose's
   * `jwtVerify`, firebase-admin's `verifyIdToken` and `verifySessionCookie`.
   * The app's own `./lib/jwt` with a `verify` that returns nothing on a bad
   * pass is not one, whatever it is called.
   */
  private throwsOnBadPass(call: Node, file: FileInfo): boolean {
    const callee = unwrap(call.callee as Node);
    if (!callee) return false;
    let root: Node | undefined = callee;
    for (let depth = 0; root && root.type !== "Identifier" && depth < 6; depth++) {
      root = unwrap((root.type === "CallExpression" ? root.callee : root.type.endsWith("MemberExpression") ? root.object : undefined) as Node | undefined);
    }
    if (root?.type !== "Identifier") return false;
    const bound = this.resolveName(String(root.name), file, 0);
    if (bound.kind !== "package") return false;
    const method = callee.type === "Identifier"
      ? bound.member
      : callee.type.endsWith("MemberExpression") && !callee.computed ? String((callee.property as Node | undefined)?.name ?? "") : "";
    if (bound.spec === "jsonwebtoken") return method === "verify";
    if (bound.spec === "jose") return method === "jwtVerify";
    if (bound.spec.startsWith("firebase-admin")) return method === "verifyIdToken" || method === "verifySessionCookie";
    return false;
  }

  /** `passport.authenticate("jwt")(req, res, next)`: the step this one hands `next` to. */
  private delegate(call: Node, file: FileInfo, hops: number): Answer {
    const callee = unwrap(call.callee as Node);
    if (!callee) return unclear("unreadable");
    const label = dottedName(callee)?.replace(/\(\)/g, "") ?? "";
    const names = identifiersIn(callee).filter((n) => !NOT_A_GUARD.test(n));
    if (names.length === 0 || /^express\b/.test(label)) return NEVER;
    return this.classifyValue(callee, file, hops + 1, label, names);
  }
}

/**
 * True when every setting is written out: plain text, numbers, or an object
 * written in place with no spread. `strategy`: the first argument must be
 * one strategy name (passport's `["jwt", "anonymous"]` lets anyone through).
 */
function readableOptions(call: Node, strategy: boolean): boolean {
  const args = (call.arguments ?? []) as Node[];
  if (strategy && !isStringLiteral(unwrap(args[0]))) return false;
  return args.every((raw) => {
    const a = unwrap(raw);
    if (!a) return false;
    if (a.type === "Literal") return true;
    if (a.type !== "ObjectExpression") return false;
    return ((a.properties ?? []) as Node[]).every((p) => p.type !== "SpreadElement");
  });
}

/** The text of a call's arguments, brackets included. */
const argumentsText = (call: Node, file: FileInfo): string =>
  file.parsed.source.slice((call.callee as Node).end, call.end);

function calls(fn: Node, name: string): boolean {
  if (!name) return false;
  let found = false;
  walk(fn.body as Node, (node) => {
    if (node.type === "CallExpression" && (node.callee as Node | undefined)?.type === "Identifier" && (node.callee as Node).name === name) found = true;
  });
  return found;
}

// --- reading a middleware body -------------------------------------------------

/** For names: bound to who is signed in ("+"), or to "not signed in" (a verify error, "-"). */
type Polarity = "+" | "-";

interface Meaning {
  whenTrue: boolean;
  whenFalse: boolean;
  mentions: boolean;
}
const NOTHING: Meaning = { whenTrue: false, whenFalse: false, mentions: false };
const SOMEONE: Meaning = { whenTrue: true, whenFalse: false, mentions: true };
const NOBODY: Meaning = { whenTrue: false, whenFalse: true, mentions: true };
const swap = (m: Meaning): Meaning => ({ whenTrue: m.whenFalse, whenFalse: m.whenTrue, mentions: m.mentions });

/** Keys under the session or context that hold who is signed in. */
const USERISH = /^(?:user|userId|user_id|userID|uid|currentUser|account|accountId|loggedIn|isLoggedIn|logged_in|auth|authenticated|isAuthenticated|member|memberId|email|sub|passport|identity|principal)$/;
const CONTEXT_KEY = /^(?:user|userId|user_id|currentUser|session|auth|jwtPayload|payload|account|accountId|claims|me|sub)$/;
/** Calls that look up who is signed in without a sign-in pass in hand. */
const IDENTITY_CALL = /^(?:getSession|getServerSession|getUser|getCurrentUser|currentUser|requireUser|auth|getAuth)$/;
/** Checks that verify a sign-in pass; their answer must still be tested. */
const VERIFY_CALL = /^(?:jwtVerify|verifyJwt|verifyJWT|verifyToken|verifyIdToken|verifyAccessToken|verifySession|verifySessionCookie|validateToken|validateSession)$/;
/** Looking a sign-in pass up where the app keeps them. A bare `get`/`has` counts only on a store named for it. */
const LOOKUP_CALL = /^(?:find\w*|lookup|load(?:User|Session|Account)\w*|getUser\w*|getSession\w*|authenticate\w*|validate(?:Session|Token|User)\w*|verify\w*)$/;
const STORE_LOOKUP = /^(?:get|has)$/;
const STORE_NAME = /session|user|auth|login|token|account|member/i;
/** Cookie and header names that carry a sign-in pass, whole names only; anti-forgery tokens are not one. */
const CREDENTIAL_NAME = /^(?:authorization|token|access[-_]?token|auth[-_]?token|id[-_]?token|jwt|auth|bearer|sid|connect\.sid|session\w*|x-access-token|x-auth-token)$/i;
const ANTI_FORGERY = /csrf|xsrf/i;
const KEY_OR_ADDRESS_HEADER = /api[-_]?key|x-api|x-forwarded-for|x-real-ip/i;

class Reading {
  private readonly identity = new Map<string, Polarity>();
  /**
   * True when a value is who is signed in itself, so it is empty exactly
   * when nobody is: `req.user`, `req.user.id`, `await getUser(req)`,
   * `verify(t) && decode(t)`. Never one that is always something: a
   * fallback (`req.user || {}`, a choice), a copy (`{ ...req.user }`,
   * `[req.user]`, a template) or a call wrapping it (`String(req.user)`).
   */
  private holdsIdentity(raw: Node): boolean {
    const node = unwrap(raw);
    if (!node) return false;
    if (node.type === "LogicalExpression" && node.operator === "&&") return this.holdsIdentity(node.left as Node);
    if (node.type === "Identifier" || node.type.endsWith("MemberExpression") || node.type === "CallExpression") return this.isIdentity(node);
    return false;
  }

  /** Declared once in the function and never written again (`let user = req.user; user = {}` is not). */
  private boundOnce(name: string): boolean {
    const b = bindingsOf(this.fn.body as Node, name);
    return b.declared === 1 && b.written === 0;
  }

  /** Names holding something the visitor sent. */
  private readonly requestValues = new Set<string>();
  /**
   * Where the step itself writes who is signed in with something that is not
   * a sign-in read (`req.user = req.query.u`, `req.user = req.user || {}`):
   * reading it back says nothing. "*" when it replaces the request itself.
   */
  private readonly overwritten = new Set<string>();
  /** What the passed tests read (`req.session.userId`), to name an inline check. */
  private readonly gates = new Set<string>();
  private readonly credentials = new Set<string>();
  private sawKeyOrAddress = false;
  private sawCredential = false;

  private readonly fn: Node;
  /** The request parameter's name (Express); "" for Hono or a destructured one. */
  private readonly req: string;
  /** The first parameter's name: the request, or Hono's context. */
  private readonly first: string;
  private readonly next: string;
  /** True for a library check, bound to its import, that throws when a pass is not genuine. */
  private readonly throws: (call: Node) => boolean;

  constructor(fn: Node, req: string, first: string, next: string, throws: (call: Node) => boolean) {
    this.fn = fn;
    this.req = req;
    this.first = first;
    this.next = next;
    this.throws = throws;
    this.learnNames();
  }

  /** Names bound to who is signed in, or to a sign-in pass, anywhere in the function. */
  private learnNames(): void {
    for (let pass = 0; pass < 3; pass++) {
      walk(this.fn.body as Node, (node) => {
        if (node.type === "VariableDeclarator" && node.init) {
          const init = node.init as Node;
          const ids = identifiersIn(node.id as Node);
          if (this.holdsIdentity(init) && ids.every((id) => this.boundOnce(id))) for (const id of ids) this.identity.set(id, "+");
          else if (this.contains(init, (n) => this.isCredential(n))) for (const id of ids) this.credentials.add(id);
          // `const want = req.query.u`, `const { u } = req.query`: a value the visitor sends.
          if (!ids.some((id) => this.identity.has(id)) && this.contains(init, (n) => this.fromRequest(n))) for (const id of ids) this.requestValues.add(id);
        }
        if (node.type === "AssignmentExpression") {
          const left = this.dotted(node.left as Node);
          if (left === this.req || left === this.first) this.overwritten.add("*");
          else if (left && !this.holdsIdentity(node.right as Node)) this.overwritten.add(left);
        }
        // `jwt.verify(token, key, (err, payload) => ...)`: the error means "not signed in".
        if (node.type === "CallExpression" && this.isVerify(node)) {
          for (const arg of (node.arguments ?? []) as Node[]) {
            if (!isFunction(arg)) continue;
            const params = (arg.params ?? []) as Node[];
            params.forEach((p, i) => { for (const id of identifiersIn(p)) this.identity.set(id, i === 0 ? "-" : "+"); });
          }
        }
      });
    }
  }

  private contains(root: Node, test: (n: Node) => boolean): boolean {
    let found = false;
    walk(root, (n) => { if (!found && test(n)) found = true; });
    return found;
  }

  private dotted(node: Node): string {
    const inner = unwrap(node);
    return inner ? dottedName(inner) ?? "" : "";
  }

  /** A header or cookie read: its name, or undefined. */
  private readName(node: Node): string | undefined {
    const name = this.dotted(node);
    const req = this.req || "req";
    if (node.type.endsWith("MemberExpression")) {
      const object = this.dotted(node.object as Node);
      const key = node.computed
        ? (isStringLiteral(node.property) ? String((node.property as Node).value) : undefined)
        : String((node.property as Node | undefined)?.name ?? "");
      // Headers and cookies; never the address, which the visitor writes in full.
      if (key !== undefined && new RegExp(`^${req}\\.(?:headers|cookies|signedCookies)$`).test(object)) return key;
      if (new RegExp(`^${req}\\.(?:ip|ips|connection\\.remoteAddress|socket\\.remoteAddress)$`).test(name)) return "x-forwarded-for";
    }
    if (node.type === "CallExpression") {
      const callee = this.dotted(node.callee as Node);
      const first = ((node.arguments ?? []) as Node[])[0];
      const second = ((node.arguments ?? []) as Node[])[1];
      if (new RegExp(`^(?:${req}\\.(?:get|header)|${this.first}\\.req\\.header|${this.first}\\.req\\.cookie)$`).test(callee) && isStringLiteral(first)) return String(first.value);
      if (/^getCookie$/.test(callee) && isStringLiteral(second)) return String(second.value);
      // `utils.jwtFrom(req)`, `tokenFrom(req)`
      if (/(?:jwt|token|bearer)\w*From|(?:get|read|extract)\w*(?:Token|Jwt|Bearer)/i.test(callee)) return "authorization";
    }
    return undefined;
  }

  private isCredential(node: Node): boolean {
    if (node.type === "Identifier" && this.credentials.has(String(node.name))) return true;
    const key = this.readName(node);
    if (key === undefined) return false;
    if (KEY_OR_ADDRESS_HEADER.test(key)) { this.sawKeyOrAddress = true; return false; }
    return CREDENTIAL_NAME.test(key) && !ANTI_FORGERY.test(key);
  }

  private isVerify(call: Node): boolean {
    const callee = this.dotted(call.callee as Node);
    const last = callee.split(".").pop() ?? "";
    const args = (call.arguments ?? []) as Node[];
    // `verifyToken(req.body.captcha)`, `verifyToken(req.headers["x-signature"])`: not a sign-in pass.
    const req = this.req || "req";
    const otherInput = args.some((a) => this.contains(a, (n) => {
      if (new RegExp(`^${req}\\.(?:body|query|params)\\b`).test(this.dotted(n))) return true;
      const key = this.readName(n);
      return key !== undefined && !(CREDENTIAL_NAME.test(key) && !ANTI_FORGERY.test(key));
    }));
    if (otherInput) return false;
    if (VERIFY_CALL.test(last)) return true;
    if (last !== "verify") return false;
    const owner = callee.split(".").slice(0, -1).join(".");
    return /jwt|jsonwebtoken|jose|jws|token|auth|firebase|session/i.test(owner) ||
      args.some((a) => this.contains(a, (n) => this.isCredential(n) || /jwt|token|bearer/i.test(this.dotted(n))));
  }

  private isOverwritten(name: string): boolean {
    if (this.overwritten.has("*")) return true;
    for (const path of this.overwritten) {
      if (name === path || name.startsWith(`${path}.`) || path.startsWith(`${name}.`)) return true;
    }
    return false;
  }

  /** Anything read from the request or handed in with it. */
  private fromRequest(node: Node): boolean {
    if (node.type !== "Identifier" && !node.type.endsWith("MemberExpression")) return false;
    const root = this.dotted(node).split(".")[0] ?? "";
    return root !== "" && (root === this.req || root === this.first || this.credentials.has(root) || this.requestValues.has(root));
  }

  /** Reads who is signed in: set by trusted code, or a pass that is verified or looked up. */
  private isIdentity(node: Node): boolean {
    if (node.type === "Identifier") return this.identity.get(String(node.name)) === "+";
    if (node.type === "CallExpression") {
      // A helper the step defines for itself (`const getUser = () => ({})`) is not the app's sign-in lookup.
      const bare = unwrap(node.callee as Node);
      if (bare?.type === "Identifier" && bindingsOf(this.fn.body as Node, String(bare.name)).declared > 0) return false;
      if (this.isVerify(node)) return true;
      const callee = this.dotted(node.callee as Node);
      const last = callee.split(".").pop() ?? "";
      const args = (node.arguments ?? []) as Node[];
      // `getUser(req)`, `auth()`, `getSession(token)`; never `getUser(id)` with an id from the address.
      const fromRequest = args.every((a) => {
        const u = unwrap(a);
        return !!u && ((u.type === "Identifier" && (u.name === this.first || u.name === this.req)) || this.contains(u, (n) => this.isCredential(n)));
      });
      if (IDENTITY_CALL.test(last) && fromRequest) return true;
      if (/^(?:isAuthenticated|isUnauthenticated)$/.test(last) && callee.startsWith(`${this.req || this.first}.`)) return true;
      // `c.get("user")`
      if (callee === `${this.first}.get` && isStringLiteral(args[0]) && CONTEXT_KEY.test(String(args[0].value))) return true;
      const owner = callee.split(".").slice(0, -1).join(".");
      const looksUp = LOOKUP_CALL.test(last) || (STORE_LOOKUP.test(last) && STORE_NAME.test(owner));
      if (looksUp && args.some((a) => this.contains(a, (n) => this.isCredential(n)))) return true;
      return false;
    }
    if (node.type.endsWith("MemberExpression")) {
      const name = this.dotted(node);
      const req = this.req;
      if (this.isOverwritten(name)) return false;
      if (req && new RegExp(`^${req}\\.(?:user|auth|oidc|kauth)(?:\\.|$)`).test(name)) return true;
      if (req && new RegExp(`^${req}\\.session\\.([\\w$]+)`).test(name)) return USERISH.test(name.split(".")[2] ?? "");
      if (/^(?:res|reply|ctx|c|context)\.(?:locals|state|var)\.([\w$]+)/.test(name)) return CONTEXT_KEY.test(name.split(".")[2] ?? "");
      const root = name.split(".")[0] ?? "";
      if (this.identity.get(root) === "+") return true;
    }
    return false;
  }

  /**
   * What a test's answer says about the visitor: `whenTrue` when the test
   * being true means someone is signed in, `whenFalse` when its being false
   * does, `mentions` when it reads who is signed in at all. Read through
   * `!`, `&&`, `||` and comparisons, so `!req.user && req.path !== "/x"`
   * (an exemption) is not mistaken for a check: its being false does not
   * mean anyone is signed in.
   */
  private meaning(raw: Node): Meaning {
    const node = unwrap(raw);
    if (!node) return NOTHING;
    if (node.type === "UnaryExpression" && node.operator === "!") return swap(this.meaning(node.argument as Node));
    if (node.type === "LogicalExpression") {
      const a = this.meaning(node.left as Node);
      const b = this.meaning(node.right as Node);
      const mentions = a.mentions || b.mentions;
      if (node.operator === "&&") return { whenTrue: a.whenTrue || b.whenTrue, whenFalse: a.whenFalse && b.whenFalse, mentions };
      if (node.operator === "||") return { whenTrue: a.whenTrue && b.whenTrue, whenFalse: a.whenFalse || b.whenFalse, mentions };
      return { whenTrue: false, whenFalse: false, mentions };
    }
    if (node.type === "BinaryExpression" && /^[!=]==?$/.test(String(node.operator))) {
      const equal = String(node.operator).startsWith("=");
      const isNothing = (n: Node) => {
        const u = unwrap(n);
        return !!u && ((u.type === "Literal" && (u.value === null || u.value === false || u.value === "" || u.value === 0)) || (u.type === "Identifier" && u.name === "undefined"));
      };
      const left = node.left as Node;
      const right = node.right as Node;
      const typeOf = (n: Node) => { const u = unwrap(n); return u?.type === "UnaryExpression" && u.operator === "typeof" ? u.argument as Node : undefined; };
      const typed = typeOf(left) ?? typeOf(right);
      // `typeof user === "undefined"`, `user == null`: true when nobody is there.
      if (typed) {
        const other = typeOf(left) ? right : left;
        const m = this.meaning(typed);
        if (isStringLiteral(other) && other.value === "undefined") return equal ? swap(m) : m;
        return equal ? { whenTrue: m.whenTrue, whenFalse: false, mentions: m.mentions } : { whenTrue: false, whenFalse: m.whenTrue, mentions: m.mentions };
      }
      if (isNothing(left) || isNothing(right)) {
        const nothing = unwrap(isNothing(left) ? left : right)!;
        const m = this.meaning(isNothing(left) ? right : left);
        // `== null` covers both empty values and `=== undefined` the one a
        // user never set has. `=== null`, `=== false`, `=== 0` and `=== ""`
        // are false for a user that was never set, so they say nothing.
        const strict = String(node.operator).length === 3;
        const coversUnset = !strict ? nothing.type === "Identifier" || nothing.value === null : nothing.type === "Identifier";
        if (!coversUnset) return { whenTrue: false, whenFalse: false, mentions: m.mentions };
        return equal ? swap(m) : m;
      }
      // `req.user.role === "admin"`: equal to something fixed means someone is
      // there. Equal to something the visitor sends (`req.query.id`), both
      // sides can be missing at once, so it says nothing.
      const sides = [this.meaning(left), this.meaning(right)];
      const which = sides.findIndex((x) => x.mentions);
      if (which < 0) return NOTHING;
      const m = sides[which]!;
      const other = which === 0 ? right : left;
      const fixed = !sides[1 - which]!.mentions && !this.contains(other, (n) => this.fromRequest(n));
      if (!fixed) return { whenTrue: false, whenFalse: false, mentions: true };
      return equal ? { whenTrue: m.whenTrue, whenFalse: false, mentions: m.mentions } : { whenTrue: false, whenFalse: m.whenTrue, mentions: m.mentions };
    }
    if (node.type === "CallExpression" && this.isIdentity(node)) {
      const last = this.dotted(node.callee as Node).split(".").pop() ?? "";
      return /^is(?:Un|Not)[A-Z]/.test(last) ? NOBODY : SOMEONE;
    }
    if (node.type === "Identifier") {
      const known = this.identity.get(String(node.name));
      return known === "+" ? SOMEONE : known === "-" ? NOBODY : NOTHING;
    }
    if (node.type.endsWith("MemberExpression")) {
      if (this.isIdentity(node)) return SOMEONE;
      const known = this.identity.get(this.dotted(node).split(".")[0] ?? "");
      if (known === "+") return SOMEONE;
      if (known === "-") return { whenTrue: false, whenFalse: false, mentions: true };
    }
    // A call given who is signed in (`isMember(req.user)`): true only for someone.
    if (node.type === "CallExpression" && this.contains(node, (n) => n !== node && this.isIdentity(n))) {
      const last = this.dotted(node.callee as Node).split(".").pop() ?? "";
      return /guest|anon|not[A-Z]|un[A-Z]|logged_?out/i.test(last) ? { whenTrue: false, whenFalse: false, mentions: true } : SOMEONE;
    }
    return this.contains(node, (n) => this.isIdentity(n)) ? { whenTrue: false, whenFalse: false, mentions: true } : NOTHING;
  }

  /** A branch that ends the request: `return ...`, `throw ...`, or a block ending in one. */
  private static leaves(branch: Node | undefined): boolean {
    if (!branch) return false;
    if (branch.type === "ReturnStatement" || branch.type === "ThrowStatement") return true;
    if (branch.type !== "BlockStatement") return false;
    const last = ((branch.body ?? []) as Node[]).at(-1);
    return last?.type === "ReturnStatement" || last?.type === "ThrowStatement";
  }

  /**
   * A plain statement (`req.user = jwt.verify(t, key);`, `const p = await
   * jwtVerify(t, key)`) whose library check throws when the pass is not
   * genuine, so the lines after it run only for a genuine one. Not inside a
   * `try` (its `catch` may carry on), a choice, or a callback; not the app's
   * own `verifyToken` or `./lib/jwt`, which may return nothing instead.
   */
  private verifiesFirst(statement: Node): boolean {
    if (statement.type !== "ExpressionStatement" && statement.type !== "VariableDeclaration") return false;
    let found = false;
    const visit = (node: Node): void => {
      if (found || FUNCTION.test(node.type) || node.type === "ConditionalExpression" || node.type === "LogicalExpression") return;
      if (node.type === "CallExpression" && !((node.arguments ?? []) as Node[]).some(isFunction) && this.throws(node)) found = true;
      for (const key of Object.keys(node)) {
        if (key === "type" || key === "start" || key === "end") continue;
        const value = node[key];
        if (Array.isArray(value)) for (const item of value) { if (item && typeof item === "object" && typeof (item as Node).type === "string") visit(item as Node); }
        else if (value && typeof value === "object" && typeof (value as Node).type === "string") visit(value as Node);
      }
    };
    visit(statement);
    return found;
  }

  /** True when the way to `node` passes a test that only someone signed in passes. */
  private gated(node: Node, parents: Node[]): boolean {
    const chain = [node, ...parents];
    /** `wants`: "+" when the test must be true to get here, "-" when it must be false. */
    const conditions: Array<{ test: Node; wants: "+" | "-" }> = [];
    for (let i = 1; i < chain.length; i++) {
      const parent = chain[i]!;
      const child = chain[i - 1]!;
      if (parent === this.fn) break;
      if (parent.type === "IfStatement" || parent.type === "ConditionalExpression") {
        if (child === parent.consequent) conditions.push({ test: parent.test as Node, wants: "+" });
        if (child === parent.alternate) conditions.push({ test: parent.test as Node, wants: "-" });
      } else if (parent.type === "LogicalExpression" && child === parent.right) {
        conditions.push({ test: parent.left as Node, wants: parent.operator === "&&" ? "+" : "-" });
      } else if (parent.type === "BlockStatement" || parent.type === "Program") {
        for (const statement of (parent.body ?? []) as Node[]) {
          if (statement === child) break;
          if (statement.type === "IfStatement") {
            const thenLeaves = Reading.leaves(statement.consequent as Node);
            const elseLeaves = Reading.leaves(statement.alternate as Node | undefined);
            if (thenLeaves && !elseLeaves) conditions.push({ test: statement.test as Node, wants: "-" });
            else if (elseLeaves && !thenLeaves) conditions.push({ test: statement.test as Node, wants: "+" });
          } else if (this.verifiesFirst(statement)) {
            this.gates.add("verified sign-in pass");
            return true;
          }
        }
      } else if (FUNCTION.test(parent.type)) {
        // `verify(token).then((user) => { ...; next(); })`
        const call = chain[i + 1];
        const callee = call?.type === "CallExpression" ? unwrap(call.callee as Node) : undefined;
        if (callee?.type.endsWith("MemberExpression") && (callee.property as Node | undefined)?.name === "then" &&
          this.contains(callee.object as Node, (n) => n.type === "CallExpression" && this.isIdentity(n))) {
          this.gates.add("verified sign-in pass");
          return true;
        }
      }
    }
    const passed = conditions.filter(({ test, wants }) => {
      const m = this.meaning(test);
      return wants === "+" ? m.whenTrue : m.whenFalse;
    });
    for (const { test } of passed) {
      walk(test, (n) => {
        if (!this.isIdentity(n)) return;
        // Named for who is signed in (`req.user`, `req.session.userId`), never
        // a property tested on it: `req.user.role` would read as a role check.
        const name = this.dotted(n.type === "CallExpression" ? n.callee as Node : n);
        const keep = name.startsWith(`${this.req}.session.`) ? 3 : 2;
        if (name) this.gates.add(name.split(".").slice(0, keep).join("."));
      });
    }
    return passed.length > 0;
  }

  answer(names: string[], delegate: (call: Node) => Answer): Answer {
    const passes: Array<{ gated: boolean; unclear?: UnclearReason; names?: string[] }> = [];
    const tests: Node[] = [];
    let refuses401 = false;
    let refusals = 0;
    const statusOf = (call: Node): number | undefined => {
      const callee = this.dotted(call.callee as Node);
      const args = (call.arguments ?? []) as Node[];
      const last = callee.split(".").pop() ?? "";
      const literal = (n: Node | undefined) => { const u = unwrap(n); return u?.type === "Literal" && typeof u.value === "number" ? u.value : undefined; };
      if (/^(?:status|sendStatus)$/.test(last)) return literal(args[0]);
      if (callee.startsWith(`${this.first}.`) && /^(?:json|text|body|html)$/.test(last)) return literal(args[1]);
      return undefined;
    };
    walk(this.fn.body as Node, (node, parents) => {
      if (node.type === "IfStatement" || node.type === "ConditionalExpression") tests.push(node.test as Node);
      if (node.type === "NewExpression" && /HTTPException|HttpError|UnauthorizedError/.test(this.dotted(node.callee as Node))) {
        refusals++;
        const status = unwrap(((node.arguments ?? []) as Node[])[0]);
        if (status?.type === "Literal" && status.value === 401) refuses401 = true;
      }
      if (node.type === "ThrowStatement") refusals++;
      if (node.type === "CallExpression") {
        const status = statusOf(node);
        if (status !== undefined) {
          refusals++;
          if (status === 401) refuses401 = true;
        }
        const callee = this.dotted(node.callee as Node);
        if (callee.endsWith(".redirect")) {
          refusals++;
          const target = ((node.arguments ?? []) as Node[]).map((a) => (isStringLiteral(a) ? String(a.value) : "")).join(" ");
          if (/log-?in|sign-?in|auth/i.test(target)) refuses401 = true;
        }
      }
      // `next()`, `next(null)`, `next(false)`, `next("")`, `next(undefined)`,
      // `next("route")` and `next("router")` carry on; `next(err)` refuses.
      if (node.type === "CallExpression" && (node.callee as Node | undefined)?.type === "Identifier" && (node.callee as Node).name === this.next) {
        const arg = unwrap(((node.arguments ?? []) as Node[])[0]);
        const carriesOn = !arg ||
          (arg.type === "Literal" && (!arg.value || arg.value === "route" || arg.value === "router")) ||
          (arg.type === "Identifier" && arg.name === "undefined");
        if (carriesOn) passes.push({ gated: this.gated(node, parents) });
        else refusals++;
        return;
      }
      // `next` handed to another step, or anywhere else.
      if (node.type === "Identifier" && node.name === this.next) {
        const parent = parents[0];
        if (parent?.type === "CallExpression" && parent.callee === node) return;
        if (FUNCTION.test(parent?.type ?? "") && ((parent!.params ?? []) as Node[]).includes(node)) return;
        if (parent?.type === "CallExpression" && ((parent.arguments ?? []) as Node[]).includes(node)) {
          const callee = unwrap(parent.callee as Node);
          // `.catch(next)` refuses with the error.
          if (callee?.type.endsWith("MemberExpression") && (callee.property as Node | undefined)?.name === "catch") { refusals++; return; }
          if (callee?.type.endsWith("MemberExpression") && (callee.property as Node | undefined)?.name === "then") {
            passes.push({ gated: this.contains(callee.object as Node, (n) => n.type === "CallExpression" && this.isIdentity(n)) || this.gated(parent, parents.slice(1)) });
            return;
          }
          const handed = delegate(parent);
          if (handed.kind === "check") passes.push({ gated: true, names: handed.names });
          else if (handed.kind === "unclear") passes.push({ gated: this.gated(parent, parents.slice(1)), unclear: handed.reason });
          else passes.push({ gated: this.gated(parent, parents.slice(1)) });
          return;
        }
        passes.push({ gated: false, unclear: "unreadable" });
      }
    });

    // It never lets anything on: it answers every request itself.
    if (passes.length === 0) return NEVER;
    if (passes.every((p) => p.gated)) {
      const handed = passes.flatMap((p) => p.names ?? []);
      const own = names.length > 0 ? names : this.gates.size > 0 ? [...this.gates] : ["sign-in check"];
      return { kind: "check", names: handed.length > 0 ? handed : own };
    }
    if (passes.some((p) => p.gated)) return unclear("exempt");
    const handedUnclear = passes.find((p) => p.unclear)?.unclear;
    if (handedUnclear) return unclear(handedUnclear);

    // Nothing on the way on tests who is signed in. A step that turns nobody
    // away (it loads the user, logs, counts) protects nothing.
    if (refusals === 0) return NEVER;
    if (tests.some((t) => this.meaning(t).mentions)) return unclear("unclear-body");
    // A test calling the app's own function named for members or sign-in (`isMember(req)`).
    const namedForWho = (t: Node) => this.contains(t, (n) => n.type === "CallExpression" && (SIGN_IN_NAME.test(this.dotted(n.callee as Node)) || /[Mm]ember|[Uu]ser|[Ss]ession|[Ll]ogged/.test(this.dotted(n.callee as Node))));
    if (tests.some(namedForWho)) return unclear("unclear-body");
    for (const test of tests) walk(test, (n) => { if (this.isCredential(n)) this.sawCredential = true; });
    if (this.sawKeyOrAddress && refusals > 0) return unclear("key-or-address");
    if (this.sawCredential && refusals > 0) return unclear("credential-only");
    // A 401 or a redirect to signing in looks like a sign-in check written
    // in a way this reading does not follow. Any other refusal (a size or
    // rate limit, a forbidden file) is about something else.
    if (refuses401) return unclear("unclear-body");
    return NEVER;
  }
}

// --- the site-wide pass ----------------------------------------------------------

interface Step {
  at: number;
  /** The function it is added in (`enclosingFunction`). */
  fn: number;
  /** Added by a helper in a nested function of its own: when it runs cannot be read. */
  unordered?: boolean;
  /** Address prefixes it applies to; empty for all; null when they cannot be read. */
  prefixes: string[] | null;
  answer: Answer;
  conditional: boolean;
  label: string;
  location: CodeLocation;
}

interface Link {
  parent: string;
  at: number;
  fn: number;
  /** Mounted or handed over under an `if`, a choice or a loop: it may not happen. */
  conditional?: boolean;
  prefix: string | null;
  file: string;
  location: CodeLocation;
}

interface ObjectInfo {
  key: string;
  file: string;
  provenance: "root" | "router" | "param" | "unknown";
  steps: Step[];
  links: Link[];
}

interface Cover {
  checks: string[];
  unclear: SignInUnclear[];
  unknown: boolean;
}

const keyOf = (file: string, scope: number, name: string) => `${file}\u0000${scope}\u0000${name}`;

/** True when an `app.use` sits under an `if`, a choice or a loop in its function. */
function underCondition(parents: Node[]): boolean {
  for (const parent of parents) {
    if (FUNCTION.test(parent.type) || parent.type === "Program") return false;
    if (/^(?:IfStatement|ConditionalExpression|LogicalExpression|SwitchStatement|ForStatement|ForInStatement|ForOfStatement|WhileStatement|DoWhileStatement)$/.test(parent.type)) return true;
  }
  return false;
}

const normalise = (prefix: string): string => prefix.replace(/\*+$/, "").replace(/\/+$/, "");

/**
 * Whether a step registered for `prefixes` runs for `path`. Express treats
 * an address as a prefix: `/api` covers `/api/orders`. Hono (`exact`) does
 * not: `/api` covers only `/api` itself, and it takes `/api/*` to cover
 * what is under it (checked against Hono 4.13.16).
 */
function matches(prefixes: string[] | null, path: string | null, exact: boolean | undefined): "yes" | "no" | "maybe" {
  if (prefixes !== null && prefixes.length === 0) return "yes";
  if (prefixes === null || path === null) return "maybe";
  // Not known to be Express or Hono: covered only when both would cover it.
  if (exact === undefined) {
    const [asExpress, asHono] = [matches(prefixes, path, false), matches(prefixes, path, true)];
    return asExpress === asHono ? asExpress : "maybe";
  }
  let maybe = false;
  for (const raw of prefixes) {
    const prefix = normalise(raw);
    if (exact && !raw.endsWith("*")) {
      // A pattern in the address (`/:id`, a bracket) cannot be compared as text.
      if (/[:*({]/.test(raw)) maybe = true;
      else if (path === raw || path === prefix) return "yes";
      continue;
    }
    if (prefix === "" || path === prefix || path.startsWith(`${prefix}/`)) return "yes";
  }
  return maybe ? "maybe" : "no";
}

function joinPath(prefix: string | null, path: string | null): string | null {
  if (prefix === null || path === null) return null;
  const head = normalise(prefix);
  if (path === "/" || path === "") return head || "/";
  return `${head}${path.startsWith("/") ? "" : "/"}${path}`;
}

/** The folder of the nearest package list above a file ("" for the repository root). */
function packageFolder(path: string, packages: Set<string>): string {
  const parts = path.split("/").slice(0, -1);
  while (parts.length > 0) {
    const folder = parts.join("/");
    if (packages.has(folder)) return folder;
    parts.pop();
  }
  return "";
}

export function applySiteWideSteps(parsedFiles: ParsedFile[], doors: Door[], allPaths: string[]): void {
  const project = new Project(parsedFiles);
  const objects = new Map<string, ObjectInfo>();
  const packages = new Set(allPaths.filter((p) => /(?:^|\/)package\.json$/.test(p)).map((p) => p.split("/").slice(0, -1).join("/")));

  /** Objects seen being made: `new Hono()`, or `express()` and its routers. */
  const madeBy = new Map<string, "hono" | "express">();
  const anyFile = project.all().map((f) => project.loads(f));
  const projectLoads = { express: anyFile.some((l) => l.express), hono: anyFile.some((l) => l.hono) };

  /**
   * Whether an app or router is Hono's (true: an address without `*` covers
   * only itself), Express's (false), or not known (undefined). Read from how
   * the object was made; for one handed in or mounted, from where it came;
   * failing that, from what its file loads, then what the project loads.
   */
  const exactCache = new Map<string, boolean | undefined>();
  const exactOf = (key: string, depth = 0): boolean | undefined => {
    if (exactCache.has(key)) return exactCache.get(key);
    const made = madeBy.get(key);
    let answer: boolean | undefined = made ? made === "hono" : undefined;
    const info = objects.get(key);
    if (answer === undefined && info && depth < MAX_HOPS) {
      for (const link of info.links) {
        const parent = link.parent ? exactOf(link.parent, depth + 1) : undefined;
        if (parent !== undefined) { answer = parent; break; }
      }
    }
    if (answer === undefined && info) {
      const file = project.fileAt(info.file);
      for (const loads of [file ? project.loads(file) : undefined, projectLoads]) {
        if (answer === undefined && loads && loads.hono !== loads.express) answer = loads.hono;
      }
    }
    if (depth === 0) exactCache.set(key, answer);
    return answer;
  };

  const objectAt = (file: FileInfo, name: string, scope: number): ObjectInfo => {
    const key = keyOf(file.path, scope, name);
    let info = objects.get(key);
    if (!info) {
      info = { key, file: file.path, provenance: provenanceOf(file, name, scope), steps: [], links: [] };
      objects.set(key, info);
    }
    return info;
  };

  /** How an object came to be: `express()` is an app; a router or a parameter needs a parent. */
  const provenanceOf = (file: FileInfo, name: string, scope: number): ObjectInfo["provenance"] => {
    if (!/^[A-Za-z_$][\w$]*$/.test(name)) return "unknown";
    let result: ObjectInfo["provenance"] = "unknown";
    walk(file.parsed.program, (node, parents) => {
      if (FUNCTION.test(node.type) && node.start === scope && ((node.params ?? []) as Node[]).some((p) => identifiersIn(p).includes(name))) result = "param";
      if (node.type !== "VariableDeclarator" || (node.id as Node).type !== "Identifier" || (node.id as Node).name !== name) return;
      if (scopeOf(name, parents) !== scope) return;
      const init = unwrap(node.init as Node | undefined);
      const made = init?.type === "CallExpression" || init?.type === "NewExpression" ? dottedName(init.callee) ?? "" : "";
      const requiredExpress = init?.type === "CallExpression" && requiredModule(init.callee as Node) === "express";
      if (made === "express" || (requiredExpress && !/Router/.test(made))) result = "root";
      else if (/(?:^|\.)Router$/.test(made) || made === "Hono" || made === "OpenAPIHono") result = made.includes("Router") ? "router" : "root";
      if (result !== "unknown") madeBy.set(keyOf(file.path, scope, name), made === "Hono" || made === "OpenAPIHono" ? "hono" : "express");
    });
    return result;
  };

  /**
   * Which export of which local file a mounted value is, read from its
   * shape: `require("./m")`, `require("./m")(x)` (`called`),
   * `require("./m").x`, a name bound to one of those, destructured from one
   * or imported from one, or `ns.x` on a whole-module name. Undefined when
   * it is not loaded from a local file at all.
   */
  type Source = { module: FileInfo; name: string; called: boolean } | { module: FileInfo; imprecise: true };
  const mountSource = (raw: Node, file: FileInfo, called = false): Source | undefined => {
    const node = unwrap(raw);
    if (!node) return undefined;
    const local = (spec: string) => project.resolveModule(file, spec);
    if (node.type === "CallExpression") {
      const callee = unwrap(node.callee as Node);
      if (callee?.type === "Identifier" && callee.name === "require") {
        const args = (node.arguments ?? []) as Node[];
        const module = isStringLiteral(args[0]) ? local(String(args[0].value)) : undefined;
        return module ? { module, name: "default", called } : undefined;
      }
      return callee ? mountSource(callee, file, true) : undefined;
    }
    if (node.type.endsWith("MemberExpression")) {
      if (node.computed) return undefined;
      const property = String((node.property as Node | undefined)?.name ?? "");
      const whole = mountSource(node.object as Node, file);
      if (!whole || "imprecise" in whole || whole.called) return whole && "imprecise" in whole ? whole : undefined;
      return whole.name === "default" || whole.name === "*" ? { module: whole.module, name: property, called } : { module: whole.module, imprecise: true };
    }
    if (node.type !== "Identifier") return undefined;
    const bound = bindingsOf(file.parsed.program, String(node.name));
    if (bound.declared !== 1 || bound.written !== 0) return undefined;
    let found: Source | undefined;
    walk(file.parsed.program, (n) => {
      if (found) return;
      if (n.type === "ImportDeclaration") {
        const module = local(String((n.source as Node).value ?? ""));
        for (const spec of (n.specifiers ?? []) as Node[]) {
          if ((spec.local as Node | undefined)?.name !== node.name || !module) continue;
          const imported = spec.type === "ImportDefaultSpecifier" ? "default" : spec.type === "ImportNamespaceSpecifier" ? "*" : String((spec.imported as Node | undefined)?.name ?? "");
          found = { module, name: imported, called };
        }
      }
      if (n.type !== "VariableDeclarator" || !n.init) return;
      const id = n.id as Node;
      const init = unwrap(n.init as Node);
      if (id.type === "Identifier" && id.name === node.name) {
        const inner = init ? mountSource(init, file) : undefined;
        if (inner && !("imprecise" in inner)) found = called ? (inner.called ? { module: inner.module, imprecise: true } : { ...inner, called: true }) : inner;
        else found = inner;
      } else if (id.type === "ObjectPattern" && identifiersIn(id).includes(String(node.name))) {
        // `const { admin } = require("./routes")`
        const inner = init ? mountSource(init, file) : undefined;
        const property = ((id.properties ?? []) as Node[]).find((p) => (p.value as Node | undefined)?.type === "Identifier" && (p.value as Node).name === node.name);
        const key = property && !property.computed ? String((property.key as Node | undefined)?.name ?? "") : "";
        if (inner && !("imprecise" in inner) && !inner.called && inner.name === "default" && key) found = { module: inner.module, name: key, called };
        else if (inner) found = { module: inner.module, imprecise: true };
      }
    });
    return found;
  };

  /**
   * The routers a file hands out under `name`: the router a name points at
   * (`module.exports = router`, `export { admin }`), or, when `called`, the
   * routers the exported function returns. "imprecise" when it cannot be
   * read that exactly.
   */
  const routersFor = (module: FileInfo, name: string, called: boolean): ObjectInfo[] | "imprecise" => {
    const values = project.exportedNodes(module, name);
    if (values.length !== 1) return "imprecise";
    let value = unwrap(values[0]);
    const routerAt = (n: string, scope: number): ObjectInfo | undefined => {
      const p = provenanceOf(module, n, scope);
      return (p === "router" || p === "root") && routedIn(module, n, scope) ? objectAt(module, n, scope) : undefined;
    };
    if (!called) {
      if (value?.type !== "Identifier") return "imprecise";
      const found = routerAt(String(value.name), -1);
      return found ? [found] : "imprecise";
    }
    if (value?.type === "Identifier") {
      const resolved = project.resolveValue(value, module, 0);
      value = resolved.kind === "function" ? resolved.fn : undefined;
    }
    if (!value || !FUNCTION.test(value.type)) return "imprecise";
    const fn = value;
    const returned: ObjectInfo[] = [];
    let other = false;
    walk(fn.body as Node, (n, parents) => {
      if (n.type !== "ReturnStatement" || parents.some((p) => FUNCTION.test(p.type) && p !== fn)) return;
      const argument = unwrap(n.argument as Node | undefined);
      const found = argument?.type === "Identifier" ? routerAt(String(argument.name), fn.start) : undefined;
      if (found) returned.push(found);
      else other = true;
    });
    return returned.length > 0 && !other ? returned : "imprecise";
  };

  /**
   * The router objects a mounted value stands for, or undefined when it is
   * not a router. A file's routers that cannot be told apart are linked to
   * an unknown parent: they may be mounted here, before or after a check.
   */
  const mountTargets = (arg: Node, file: FileInfo, parents: Node[]): ObjectInfo[] | undefined => {
    const node = unwrap(arg);
    if (!node) return undefined;
    if (node.type === "Identifier") {
      const name = String(node.name);
      const scope = scopeOf(name, parents);
      const provenance = provenanceOf(file, name, scope);
      if (provenance === "router" || (provenance === "root" && routedIn(file, name, scope))) return [objectAt(file, name, scope)];
    }
    const source = mountSource(node, file);
    if (!source || source.module === file) return undefined;
    const routers = routersIn(source.module);
    if (routers.length === 0) return undefined;
    const exact = "imprecise" in source ? "imprecise" : routersFor(source.module, source.name, source.called);
    if (exact !== "imprecise") return exact;
    for (const router of routers) {
      router.links.push({ parent: "", at: 0, fn: -1, prefix: null, file: file.path, location: locationOf(file.parsed, node) });
    }
    return [];
  };

  /** Routes registered in a file on `name` in that scope. */
  const routedIn = (file: FileInfo, name: string, scope: number): boolean =>
    doors.some((d) => d.location.path === file.path && routeSeen.get(d)?.object === name && routeSeen.get(d)?.scope === scope);

  const routersIn = (file: FileInfo): ObjectInfo[] => {
    const seen = new Map<string, ObjectInfo>();
    for (const door of doors) {
      if (door.location.path !== file.path) continue;
      const where = routeSeen.get(door);
      if (!where) continue;
      const info = objectAt(file, where.object, where.scope);
      if (info.provenance === "router" || info.provenance === "root") seen.set(info.key, info);
    }
    return [...seen.values()];
  };

  const prefixesOf = (arg: Node | undefined, file: FileInfo): string[] | null | undefined => {
    const node = unwrap(arg);
    if (!node) return undefined;
    if (isStringLiteral(node)) return [String(node.value)];
    if (node.type === "ArrayExpression") {
      const items = (node.elements ?? []) as Node[];
      // A list of addresses; a list with no address in it is a list of steps.
      if (items.length > 0 && !items.some((i) => isStringLiteral(i) || i?.type === "TemplateLiteral" || (i?.type === "Literal" && i.regex))) return undefined;
      return items.every((i) => isStringLiteral(i)) ? items.map((i) => String(i.value)) : null;
    }
    if (node.type === "TemplateLiteral" || (node.type === "Literal" && node.regex)) return null;
    if (node.type === "Identifier") {
      const bound = bindingsOf(file.parsed.program, String(node.name));
      if (bound.declared !== 1 || bound.written !== 0) return undefined;
      let value: string | undefined;
      walk(file.parsed.program, (n) => {
        if (n.type === "VariableDeclarator" && (n.id as Node).type === "Identifier" && (n.id as Node).name === node.name && isStringLiteral(unwrap(n.init as Node))) value = String(unwrap(n.init as Node)!.value);
      });
      return value === undefined ? undefined : [value];
    }
    return undefined;
  };

  /** True when an argument reads as a step or a router rather than an address. */
  const looksLikeStep = (arg: Node, file: FileInfo, parents: Node[]): boolean => {
    const node = unwrap(arg);
    if (!node) return false;
    if (isFunction(node)) return true;
    if (node.type === "CallExpression") {
      // `app.use(base(), check)`, `app.use(config.get("prefix"), check)`: an address made by a call.
      const label = dottedName(unwrap(node.callee as Node)) ?? "";
      const last = label.split(".").pop() ?? "";
      if (/^(?:get|path|prefix|url|join|resolve|format|concat|toString|base\w*)$/i.test(last) || /Path|PATH|Prefix|PREFIX|Url|URL|Base|BASE/.test(label)) return false;
      if (requiredModule(node) !== undefined || NOT_A_GUARD.test(last) || SESSION_SETUP.test(label) || SIGN_IN_NAME.test(label)) return true;
      // A middleware library, passport, or the app's own function that returns a step.
      const resolved = project.resolveValue(unwrap(node.callee as Node)!, file, 0);
      if (resolved.kind === "package") return true;
      if (resolved.kind === "function") {
        const made = project.classifyStep(node, file).answer;
        return made.kind !== "unclear" || made.reason !== "unreadable";
      }
      return false;
    }
    if (node.type !== "Identifier" && !node.type.endsWith("MemberExpression")) return false;
    const resolved = project.resolveValue(node, file, 0);
    if (resolved.kind === "function" || resolved.kind === "package" || resolved.kind === "call" || resolved.kind === "module") return true;
    if (mountTargets(node, file, parents)) return true;
    const label = dottedName(node) ?? "";
    return SIGN_IN_NAME.test(label) && !/(?:Path|PATH|Prefix|PREFIX|Url|URL|Base|BASE|Route)$/.test(label);
  };

  // 1. Steps and mounts, file by file.
  const handOffs: Array<{ file: FileInfo; call: Node; parents: Node[] }> = [];
  for (const file of project.all()) {
    walk(file.parsed.program, (node, parents) => {
      if (node.type !== "CallExpression") return;
      const args = (node.arguments ?? []) as Node[];
      if (args.some((a) => a.type === "Identifier" && ROUTER.test(String(a.name)))) handOffs.push({ file, call: node, parents });
      const callee = node.callee as Node | undefined;
      if (!callee?.type.endsWith("MemberExpression") || callee.computed) return;
      const objectName = dottedName(callee.object);
      const property = dottedName(callee.property);
      if (!objectName || !property || !ROUTER.test(objectName.split(".").pop() ?? "")) return;
      const wildcardAll = property === "all" && isStringLiteral(args[0]) && /\*/.test(String(args[0].value));
      if (property !== "use" && property !== "route" && !wildcardAll) return;

      const object = objectAt(file, objectName, scopeOf(objectName, parents));
      let prefixes = prefixesOf(args[0], file);
      // `app.use(API_PREFIX, requireAuth)`: a first argument that is not a
      // step is an address that could not be read, never "every address".
      if (prefixes === undefined && args.length >= 2 && !looksLikeStep(args[0]!, file, parents)) prefixes = null;
      const rest = prefixes === undefined ? args : args.slice(1);
      const conditional = underCondition(parents);
      // `app.use([logger, requireLogin])`: each one is a step of its own.
      const each = rest.flatMap((a) => (unwrap(a)?.type === "ArrayExpression" ? ((unwrap(a)!.elements ?? []) as Node[]) : [a]));
      for (const arg of each) {
        const targets = mountTargets(arg, file, parents);
        if (targets) {
          for (const prefix of prefixes === undefined ? [""] : prefixes === null ? [null] : prefixes) {
            for (const target of targets) {
              if (target.key === object.key) continue;
              target.links.push({ parent: object.key, at: arg.start, fn: enclosingFunction(parents), conditional, prefix, file: file.path, location: locationOf(file.parsed, arg) });
            }
          }
          continue;
        }
        if (property === "route") continue;
        const step = project.classifyStep(arg, file);
        object.steps.push({
          at: arg.start,
          fn: enclosingFunction(parents),
          // `undefined`: no address given, so every address; `null`: one that could not be read.
          prefixes: prefixes === undefined ? [] : prefixes,
          answer: step.answer,
          conditional: conditional || step.conditional === true,
          label: step.label,
          location: locationOf(file.parsed, arg),
        });
      }
    });
  }

  // Every object a route is registered on, so a parameter one can be linked to its caller.
  for (const door of doors) {
    const where = routeSeen.get(door);
    const file = where ? project.fileAt(door.location.path) : undefined;
    if (where && file) objectAt(file, where.object, where.scope);
  }

  // 2. Files handed the app: `routes(app, db)`, `require("./routes")(app)`.
  for (const info of objects.values()) {
    if (info.provenance !== "param") continue;
    const [path, scopeText, name] = info.key.split("\u0000") as [string, string, string];
    const file = project.fileAt(path)!;
    let fn: Node | undefined;
    walk(file.parsed.program, (n) => { if (FUNCTION.test(n.type) && n.start === Number(scopeText)) fn = n; });
    if (!fn) continue;
    const index = ((fn.params ?? []) as Node[]).findIndex((p) => p.type === "Identifier" && p.name === name);
    if (index < 0) continue;
    for (const { file: callerFile, call, parents } of handOffs) {
      const arg = ((call.arguments ?? []) as Node[])[index];
      if (arg?.type !== "Identifier" || !ROUTER.test(String(arg.name))) continue;
      let target = project.resolveValue(call.callee as Node, callerFile, 0);
      if (target.kind === "module") target = project.exported(target.file, "default", 1);
      if (target.kind !== "function" || target.fn !== fn) continue;
      const parent = objectAt(callerFile, String(arg.name), scopeOf(String(arg.name), parents));
      if (parent.key === info.key) continue;
      info.links.push({ parent: parent.key, at: call.start, fn: enclosingFunction(parents), conditional: underCondition(parents), prefix: "", file: callerFile.path, location: locationOf(callerFile.parsed, call) });
    }
  }

  // Steps a helper adds to the app it is handed (`applyMiddleware(app)`)
  // run where the helper is called, on the app it was given.
  const copied = new Set<Step>();
  for (let round = 0; round < MAX_HOPS; round++) {
    for (const info of objects.values()) {
      if (info.provenance !== "param" || info.links.length === 0) continue;
      const scope = Number(info.key.split("\u0000")[1]);
      for (const step of info.steps) {
        if (copied.has(step)) continue;
        copied.add(step);
        for (const link of info.links) {
          const parent = objects.get(link.parent);
          if (!parent || link.prefix !== "") continue;
          parent.steps.push({
            ...step,
            at: link.at,
            fn: link.fn,
            conditional: step.conditional || link.conditional === true,
            unordered: step.unordered === true || step.fn !== scope,
          });
        }
      }
    }
  }

  // 3. What covers each route.
  const cover = (key: string, at: number, fn: number, path: string | null, hops: number, visiting: Set<string>): Cover => {
    const info = objects.get(key);
    if (!info || visiting.has(key)) return { checks: [], unclear: [], unknown: true };
    const checks: string[] = [];
    const unclears: SignInUnclear[] = [];
    for (const step of info.steps) {
      // Another function's step may run before, after, or never.
      const ordered = step.fn === fn && !step.unordered;
      if (ordered && step.at >= at) continue;
      const fit = matches(step.prefixes, path, exactOf(key));
      if (fit === "no") continue;
      const label = step.label;
      if (step.answer.kind === "check") {
        if (!ordered) unclears.push({ step: label, location: step.location, reason: "order" });
        else if (step.conditional) unclears.push({ step: label, location: step.location, reason: "conditional" });
        else if (fit === "maybe") unclears.push({ step: label, location: step.location, reason: "some-addresses" });
        else checks.push(...step.answer.names);
      } else if (step.answer.kind === "unclear") {
        unclears.push({ step: label, location: step.location, reason: step.answer.reason });
      }
    }
    if (checks.length > 0) return { checks, unclear: [], unknown: false };
    if (info.links.length === 0) return { checks, unclear: unclears, unknown: info.provenance !== "root" };
    if (hops >= MAX_HOPS) return { checks, unclear: unclears, unknown: true };
    const inner = new Set([...visiting, key]);
    const results = info.links.map((link) => {
      const result = cover(link.parent, link.at, link.fn, joinPath(link.prefix, path), hops + (link.file === info.file ? 0 : 1), inner);
      // Covered only if the mount or hand-over happens at all.
      if (link.conditional && result.checks.length > 0) {
        return { link, result: { checks: [], unclear: [{ step: "", location: link.location, reason: "conditional" as const }], unknown: false } };
      }
      return { link, result };
    });
    const covered = results.filter((r) => r.result.checks.length > 0);
    if (covered.length === results.length) return { checks: covered.flatMap((r) => r.result.checks), unclear: [], unknown: false };
    if (covered.length > 0) {
      const open = results.find((r) => r.result.checks.length === 0)!;
      return { checks: [], unclear: [...unclears, { step: "", location: open.link.location, reason: "mounted-twice" }], unknown: false };
    }
    return {
      checks: [],
      unclear: [...unclears, ...results.flatMap((r) => r.result.unclear)],
      unknown: results.some((r) => r.result.unknown),
    };
  };

  // A sign-in check for everything after it, on an app, per package folder.
  const siteWideChecks = new Map<string, Step>();
  for (const info of objects.values()) {
    if (info.provenance !== "root") continue;
    for (const step of info.steps) {
      // One added by a helper at a time that cannot be read is not "the app's check".
      if (step.answer.kind !== "check" || step.conditional || step.unordered || matches(step.prefixes, "/", exactOf(info.key)) !== "yes" || (step.prefixes ?? []).some((p) => normalise(p) !== "")) continue;
      const folder = packageFolder(info.file, packages);
      if (!siteWideChecks.has(folder)) siteWideChecks.set(folder, step);
    }
  }

  for (const door of doors) {
    const where = routeSeen.get(door);
    if (!where) continue;
    const key = keyOf(door.location.path, where.scope, where.object);
    const result = cover(key, where.at, where.fn, door.path, 0, new Set());
    if (result.checks.length > 0) {
      for (const name of result.checks) if (!door.guards.includes(name)) door.guards.push(name);
      continue;
    }
    if (door.guards.length > 0) continue;
    const seen = new Set<string>();
    const unclears = result.unclear.filter((u) => {
      const id = `${u.location.path}:${u.location.line}:${u.reason}`;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
    if (unclears.length > 0) {
      door.signInUnclear = unclears;
      continue;
    }
    if (result.unknown) {
      const check = siteWideChecks.get(packageFolder(door.location.path, packages));
      if (check && check.location.path !== door.location.path) {
        door.signInUnclear = [{ step: check.label, location: check.location, reason: "mount" }];
      }
    }
  }
}
