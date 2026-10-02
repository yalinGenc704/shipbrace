import type { RepoSnapshot } from "../types.ts";
import { isTestPath } from "../util.ts";
import {
  contains,
  dottedName,
  identifiersIn,
  isStringLiteral,
  locationOf,
  parseFile,
  textOf,
  walk,
  type Node,
  type ParsedFile,
} from "./ast.ts";
import type {
  Assignment,
  Door,
  Inventory,
  Sanitizer,
  Sink,
  SinkKind,
  SourceKind,
  TaintSource,
} from "./inventory.ts";

/**
 * The attack-surface inventory, built from parsed syntax rather than matched
 * text. Produces exactly the shapes the oracle already consumes, so it is a
 * drop-in replacement for the regex version.
 */

const ROUTER = /^(?:app|router|\w*[Rr]outes?)$/;
const METHODS = new Set(["get", "post", "put", "patch", "delete", "all"]);

/** Middleware that is not an access-control check; naming it as a guard would hide a missing one. */
const ACCESS_CHECK =
  /auth|login|signed|session|guard|protect|require(?:User|Login|Admin|Role)|verify(?:Token|Jwt|User)|jwt|deny|permission|role|admin|acl|userId/i;

const NOT_A_GUARD =
  /^(?:cors|secureHeaders|logger|compress|compression|etag|prettyJSON|rateLimiter|rateLimit|limiter|helmet|morgan|bodyParser|json|urlencoded|cookieParser|express|upload|multer|serveStatic|cache|validate\w*)$/;

const SOURCE_NAMES: Array<{ match: RegExp; kind: SourceKind }> = [
  // Express with multer: `req.file.originalname` is whatever the uploader named it.
  { match: /\breq\.files?$/, kind: "uploaded-file" },
  { match: /\breq\.params?$/, kind: "route-param" },
  { match: /\breq\.quer(?:y|ies)$/, kind: "query-string" },
  { match: /\breq\.(?:json|text|parseBody|formData|body)$/, kind: "request-body" },
  { match: /\breq\.header$/, kind: "header" },
  { match: /^getCookie$/, kind: "cookie" },
];

/**
 * How code asks who is signed in.
 *
 * Hono middleware stores the user on the context (`c.set("userId", ...)`,
 * read back with `c.get("userId")` or `c.var.userId`); other stacks attach it
 * to the request or call a session helper. Names are matched exactly so an
 * unrelated `cache.get("user")` is not mistaken for one.
 */
const IDENTITY_KEY =
  /^(?:user|userId|user_id|currentUser|session|auth|jwtPayload|payload|account|accountId|claims|me|sub)$/;
const CONTEXT_OBJECT = /^(?:c|ctx|context)$/;
const IDENTITY_CALL =
  /^(?:getSession|getServerSession|getUser|getCurrentUser|currentUser|requireUser|auth|getAuth)$/;

function isIdentityRead(node: Node): boolean {
  if (node.type === "CallExpression") {
    const name = dottedName(node.callee) ?? "";
    const parts = name.split(".");
    const first = ((node.arguments ?? []) as Node[])[0];
    if (
      parts.length === 2 && CONTEXT_OBJECT.test(parts[0]!) && parts[1] === "get" &&
      isStringLiteral(first) && IDENTITY_KEY.test(String(first.value))
    ) {
      return true;
    }
    return IDENTITY_CALL.test(parts.at(-1) ?? "");
  }
  if (node.type === "MemberExpression") {
    const name = dottedName(node) ?? "";
    const parts = name.split(".");
    // `c.var.userId`, `ctx.state.user`, `res.locals.user`, `req.user`
    if (parts.length === 3 && /^(?:var|state|locals)$/.test(parts[1]!)) {
      return IDENTITY_KEY.test(parts[2]!);
    }
    return parts.length === 2 && parts[0] === "req" && /^(?:user|session|auth)$/.test(parts[1]!);
  }
  return false;
}

/** Calls that show or record a value without deciding anything with it. */
const DISPLAY = /(?:^|\.)(?:render|json|send|write|end|html|text|flash|log|info|warn|error|debug)$/;

/**
 * Record lookups through a database library -- Sequelize, Prisma, Mongoose,
 * TypeORM. They send values as data, so they are never an injection problem;
 * they matter only for "whose record is this?". Required to be called on a
 * model (`User.find`, `db.User.find`, `prisma.user.update`) so that an array's
 * `.find` or a hash's `.update` is not mistaken for one.
 */
const ORM_METHOD =
  /^(?:findOne|findByPk|findById|findUnique|findFirst|findAll|findMany|find|update|updateOne|updateMany|destroy|delete|deleteOne|deleteMany|findOneAndUpdate|findByIdAndUpdate|findByIdAndDelete|findOneAndDelete|upsert)$/;
const MODEL_OWNER = /^(?:db|prisma|models?|repo|repository|knex)$|^[A-Z]/;

const SHELL = /^(?:execSync|exec|execFile|execFileSync|spawn|spawnSync)$/;
const FILESYSTEM =
  /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|rm|rmSync|createReadStream|createWriteStream|open)$/;
/**
 * Turning text into running code. `unserialize` is node-serialize's: it
 * rebuilds functions from the text it is given, so whoever wrote the text
 * chooses what runs.
 */
const DYNAMIC_CODE = /^(?:eval|vm\.runIn(?:New|This)?Context|vm\.compileFunction)$|(?:^|\.)unserialize$/;

/** Bun's own file calls. Matched exactly: `stream.write` is not a file path. */
const BUN_FILE = /^Bun\.(?:write|file)$/;

/** A template's literal text, with the interpolation slots removed. */
function quasiText(template: Node): string {
  const quasis = (template.quasis ?? []) as Array<{ value?: { cooked?: string; raw?: string } }>;
  return quasis.map((q) => q.value?.cooked ?? q.value?.raw ?? "").join(" \u0000 ");
}

/**
 * A recognisable SQL statement needs two paired keywords. One alone matches
 * ordinary prose -- a template mentioning a variable called `where` is not a
 * query. Applied to template text only, never to arbitrary file content.
 */
const SQL_STATEMENT =
  /\b(?:SELECT\b[\s\S]*?\bFROM|INSERT\s+INTO\b[\s\S]*?\bVALUES|UPDATE\b[\s\S]*?\bSET|DELETE\s+FROM)\b/i;

/** Tags that parameterise their interpolations, making the template safe by construction. */
const SAFE_TAG = /(?:^|\.)(?:sql|db|query)$/i;

export function buildInventoryFromAst(snapshot: RepoSnapshot): Inventory {
  const views = new Map(
    snapshot.files.filter((f) => TEMPLATE.test(f.path)).map((f) => [f.path, f.content]),
  );
  const inventory: Inventory = {
    doors: [],
    sources: [],
    sinks: [],
    sanitizers: [],
    assignments: [],
  };

  for (const file of snapshot.files) {
    if (isTestPath(file.path)) continue;

    const parsed = parseFile(file);
    if (!parsed) continue;

    const doors = findDoors(parsed);
    inventory.doors.push(...doors);
    collect(parsed, doors, inventory, views);
  }

  // A route that names its handler gets that function's code, when exactly one
  // function of that name exists. Two of the same name is a guess, so neither.
  for (const door of inventory.doors) {
    if (!door.handlerRef) continue;
    const matches = (inventory.functions ?? []).filter((f) => f.name === door.handlerRef);
    if (matches.length === 1) door.handlerAt = { path: matches[0]!.path, range: matches[0]!.bodyRange };
  }
  return inventory;
}

/** Page templates, which are text rather than code but decide what is escaped. */
const TEMPLATE = /\.(?:ejs|hbs|handlebars|pug|njk|swig|html)$/i;

function doorFor(doors: Door[], node: Node): Door | undefined {
  let innermost: Door | undefined;
  for (const door of doors) {
    const [start, end] = door.bodyRange;
    if (node.start < start || node.end > end) continue;
    if (!innermost || start > innermost.bodyRange[0]) innermost = door;
  }
  return innermost;
}

function findDoors(parsed: ParsedFile): Door[] {
  const registered: Array<{ prefix: string; names: string[] }> = [];
  const routes: Array<{ method: string; path: string; node: Node; handler: Node; middleware: Node[] }> = [];

  walk(parsed.program, (node) => {
    if (node.type !== "CallExpression") return;

    const callee = node.callee as Node | undefined;
    if (!callee || callee.type !== "MemberExpression") return;

    const object = dottedName(callee.object);
    const property = dottedName(callee.property);
    if (!object || !property || !ROUTER.test(object.split(".").pop() ?? "")) return;

    const args = (node.arguments ?? []) as Node[];

    if (property === "use") {
      const prefix = isStringLiteral(args[0]) ? String(args[0].value).replace(/\*+$/, "") : "";
      const names = args
        .filter((a) => !isStringLiteral(a))
        .flatMap((a) => identifiersIn(a))
        .filter((n) => !NOT_A_GUARD.test(n));

      if (names.length > 0) registered.push({ prefix, names });
      return;
    }

    if (!METHODS.has(property) || !isStringLiteral(args[0])) return;

    // The handler is the last argument; its body is the analysis scope.
    const handler = args.at(-1);
    routes.push({
      method: property.toUpperCase(),
      path: String(args[0].value),
      node,
      handler: handler ?? node,
      // Everything between the path and the handler runs first, on this
      // route only: `router.get("/admin", requireLogin, handler)`.
      middleware: args.slice(1, -1),
    });
  });

  return routes.map(({ method, path, node, handler, middleware }): Door => {
    const guards = new Set<string>();
    /**
     * Checks named on the route itself count as much as ones registered for a
     * prefix. Missing them reported every route of a typical Express app as
     * open to anyone -- 27 warnings on one app whose routes were all protected.
     */
    for (const name of middleware.flatMap((m) => identifiersIn(m))) {
      if (!NOT_A_GUARD.test(name)) guards.add(name);
    }
    /**
     * `app.post("/api/Products", security.isAuthorized())` -- the only thing
     * after the path is a check, and the real handler is registered elsewhere.
     * It sits where a handler would, and `app.get("/x", search())` looks the
     * same, so it counts only when its name says it is an access check.
     */
    if (middleware.length === 0 && handler.type === "CallExpression") {
      const callee = dottedName(handler.callee) ?? "";
      if (ACCESS_CHECK.test(callee)) guards.add(callee);
    }
    for (const entry of registered) {
      if (entry.prefix === "" || path.startsWith(entry.prefix)) {
        for (const name of entry.names) guards.add(name);
      }
    }

    const named = handler.type === "Identifier" || handler.type === "MemberExpression"
      ? dottedName(handler)?.split(".").pop()
      : undefined;

    return {
      id: `${parsed.path}:${method}:${path}`,
      method,
      path,
      location: locationOf(parsed, node),
      guards: [...guards],
      bodyRange: [handler.start, handler.end],
      ...(named ? { handlerRef: named } : {}),
    };
  });
}

function collect(
  parsed: ParsedFile,
  doors: Door[],
  into: Inventory,
  views: Map<string, string> = new Map(),
): void {
  walk(parsed.program, (node, parents) => {
    const door = doorFor(doors, node);
    const doorId = door ? { doorId: door.id } : {};

    // --- sources ---------------------------------------------------------
    const sourceKind = sourceKindOf(node, parents);
    if (sourceKind) {
      const binding = bindingFor(parents);
      into.sources.push({
        id: `${parsed.path}:src:${node.start}`,
        kind: sourceKind,
        expression: textOf(parsed, fieldOf(node, parents)).slice(0, 160),
        ...(binding ? { binding } : {}),
        location: locationOf(parsed, node),
        ...doorId,
      });
    }

    // --- who is signed in -----------------------------------------------
    if (isIdentityRead(node)) {
      // The nearest call it is passed into, if that call only displays it.
      const call = parents.find((p) => p.type === "CallExpression" && p !== node);
      const displayOnly = Boolean(call) &&
        DISPLAY.test(dottedName(call!.callee) ?? "") &&
        !parents.some((p) => p.type === "VariableDeclarator" || p.type === "AssignmentExpression");
      (into.identities ??= []).push({
        id: `${parsed.path}:who:${node.start}`,
        expression: textOf(parsed, node).slice(0, 120),
        location: locationOf(parsed, node),
        ...doorId,
        ...(displayOnly ? { displayOnly } : {}),
      });
    }

    // --- assignments -----------------------------------------------------
    if (node.type === "VariableDeclarator") {
      const id = node.id as Node | undefined;
      const init = node.init as Node | undefined;

      if (id?.type === "Identifier" && init) {
        into.assignments.push({
          id: `${parsed.path}:asg:${node.start}`,
          target: String(id.name ?? ""),
          from: identifiersIn(init),
          location: locationOf(parsed, node),
          ...doorId,
        });

        const kind = sanitizerKindOf(init, parsed);
        if (kind) {
          into.sanitizers.push({
            id: `${parsed.path}:san:${node.start}`,
            kind,
            guards: [String(id.name ?? ""), ...identifiersIn(init)],
            location: locationOf(parsed, node),
            ...doorId,
          });
        }
      }
    }

    /**
     * `output = { searchTerm: req.body.name }` -- a plain reassignment, no
     * `const`. Common in older code, and invisible until now, so a value that
     * travelled through one was lost.
     */
    if (node.type === "AssignmentExpression" && node.operator === "=") {
      const left = node.left as Node | undefined;
      const right = node.right as Node | undefined;
      if (left?.type === "Identifier" && right) {
        const target = String(left.name ?? "");
        into.assignments.push({
          id: `${parsed.path}:asg:${node.start}`,
          target,
          from: identifiersIn(right),
          location: locationOf(parsed, node),
          ...doorId,
        });
        const kind = sanitizerKindOf(right, parsed);
        if (kind) {
          into.sanitizers.push({
            id: `${parsed.path}:san:${node.start}`,
            kind,
            guards: [target, ...identifiersIn(right)],
            location: locationOf(parsed, node),
            ...doorId,
          });
        }
      }
    }

    // --- call sites ------------------------------------------------------
    if (node.type === "CallExpression") {
      const callee = dottedName(node.callee);
      if (callee) {
        (into.calls ??= []).push({
          id: `${parsed.path}:call:${node.start}`,
          callee,
          args: ((node.arguments ?? []) as Node[]).map((a) => identifiersIn(a)),
          path: parsed.path,
        });
      }
    }

    // An allowlist test guards whatever it is checking -- unless it plainly
    // cannot stop anything. See `decidesNothing`.
    if (node.type === "CallExpression") {
      const name = dottedName(node.callee) ?? "";
      if (/\.(?:includes|has|indexOf)$/.test(name) && !decidesNothing(node, parents)) {
        into.sanitizers.push({
          id: `${parsed.path}:san:${node.start}`,
          kind: "allowlist",
          guards: identifiersIn(node),
          location: locationOf(parsed, node),
          ...doorId,
        });
      }
    }

    // --- functions -------------------------------------------------------
    if (/^(?:FunctionDeclaration|FunctionExpression|ArrowFunctionExpression)$/.test(node.type)) {
      const body = (node.body as Node | undefined) ?? node;
      const declared = (node.id as Node | undefined)?.name;
      // `const f = ...`, `module.exports.f = ...`, `exports.f = ...`, `{ f: ... }`
      const parent = parents[0];
      const assigned = parent?.type === "VariableDeclarator"
        ? ((parent.id as Node | undefined)?.name)
        : parent?.type === "AssignmentExpression" && parent.right === node
        ? (dottedName(parent.left)?.split(".").pop())
        : (parent?.type === "Property" || parent?.type === "ObjectProperty") && parent.value === node
        ? ((parent.key as Node | undefined)?.name ?? (isStringLiteral(parent.key) ? parent.key.value : undefined))
        : undefined;

      (into.functions ??= []).push({
        id: `${parsed.path}:fn:${node.start}`,
        name: String(declared ?? assigned ?? ""),
        params: ((node.params ?? []) as Node[]).map((p) =>
          p.type === "Identifier" ? String(p.name ?? "") : ""
        ),
        bodyRange: [body.start, body.end],
        path: parsed.path,
      });
    }

    // --- sinks -----------------------------------------------------------
    const sink = sinkFor(parsed, node, parents, views);
    if (sink) into.sinks.push({ ...sink, ...doorId });
  });
}

/**
 * `req.body.id`, not just `req.body`: the field read is what a suggestion
 * names ("the id in the form"), and what tells two inputs apart.
 */
function fieldOf(node: Node, parents: Node[]): Node {
  let current = node;
  for (const parent of parents) {
    if (parent.type !== "MemberExpression" || parent.object !== current || parent.computed) break;
    current = parent;
  }
  return current;
}

function sourceKindOf(node: Node, parents: Node[]): SourceKind | undefined {
  if (node.type !== "CallExpression" && node.type !== "MemberExpression") return undefined;

  // `c.req.param("id")` is one source, not two. The member expression and the
  // call that wraps it both match the pattern, so the inner one is skipped --
  // otherwise every source is counted twice and every finding duplicated.
  if (node.type === "MemberExpression") {
    const parent = parents[0];
    if (parent?.type === "CallExpression" && parent.callee === node) return undefined;
  }

  // For a call, the interesting name is the callee: c.req.param("id").
  const name = node.type === "CallExpression"
    ? dottedName(node.callee) ?? ""
    : dottedName(node) ?? "";

  for (const { match, kind } of SOURCE_NAMES) {
    if (match.test(name)) return kind;
  }
  if (node.type === "CallExpression" && name === "fetch") return "external-response";

  /**
   * Files read out of someone else's GitHub repository. Whoever controls the
   * repository controls this content, so it is as untrusted as a form field --
   * the case that matters most for a product that reviews other people's code.
   */
  if (node.type === "CallExpression" && REPO_CONTENT.test(name)) return "repo-content";

  if (node.type === "MemberExpression" && OUTSIDER_ENV.test(name)) return "environment";
  return undefined;
}

const REPO_CONTENT =
  /(?:^|\.)(?:getContent|getBlob|getReadme|downloadTarballArchive|downloadZipballArchive)$/;

/**
 * Settings values are normally chosen by whoever runs the app and are
 * trusted: flagging `process.env.DATABASE_URL` would be a warning on correct
 * code. These few are the exception. In an automated build, a pull request's
 * branch name, title, or description is written by whoever opened it --
 * possibly a stranger -- and has been used to run commands on build servers.
 */
const OUTSIDER_ENV =
  /^(?:process\.env|Bun\.env|import\.meta\.env)\.(?:GITHUB_HEAD_REF|PR_TITLE|PR_BODY|PULL_REQUEST_TITLE|PULL_REQUEST_BODY|ISSUE_TITLE|ISSUE_BODY|COMMENT_BODY|HEAD_COMMIT_MESSAGE|COMMIT_MESSAGE)$/;

/** The variable a node's value is being assigned to, if any. */
function bindingFor(parents: Node[]): string | undefined {
  for (const parent of parents) {
    if (parent.type === "VariableDeclarator") {
      const id = parent.id as Node | undefined;
      if (id?.type === "Identifier") return String(id.name ?? "");

      // `const { url } = c.req.query()` -- the first name is enough to anchor it.
      if (id?.type === "ObjectPattern") {
        const names = identifiersIn(id);
        return names[0];
      }
      return undefined;
    }
    if (parent.type === "AssignmentExpression") {
      const left = parent.left as Node | undefined;
      return left?.type === "Identifier" ? String(left.name ?? "") : undefined;
    }
    // Stop at a function boundary: an outer declarator is a different statement.
    if (/Function|ArrowFunctionExpression/.test(parent.type)) return undefined;
  }
  return undefined;
}

/**
 * An `if` whose test is this check, and neither branch leaves -- no return, no
 * throw. `if (next.includes("://")) console.warn(...)` looks at the value and
 * then carries on regardless. Counting that as validation hid an open
 * redirect. Anything less clear-cut (the result stored in a variable, used in
 * an expression) still counts, because wrongly ignoring a real check would
 * report correct code as broken.
 */
function decidesNothing(call: Node, parents: Node[]): boolean {
  const branch = parents.find(
    (p) => p.type === "IfStatement" && p.test && contains(p.test as Node, call),
  );
  if (!branch) return false;

  let exits = false;
  for (const side of [branch.consequent, branch.alternate] as Array<Node | undefined>) {
    if (!side) continue;
    walk(side, (n) => {
      if (n.type === "ReturnStatement" || n.type === "ThrowStatement") exits = true;
    });
  }
  return !exits;
}

/**
 * Validators that leave a value free-form text. A schema built only from
 * these confirms the shape of the data, not that its contents are harmless:
 * `z.object({ name: z.string() })` lets any text through, query commands
 * included.
 */
const FREE_TEXT = new Set(["string", "any", "unknown"]);
const STRUCTURE = new Set(["object", "array", "optional", "nullable", "record", "tuple", "union", "strictObject", "looseObject"]);
const CONSTRAINS = /\.(?:uuid|email|url|regex|cuid2?|ulid|datetime|date|time|ip|ipv4|ipv6|base64|nanoid|emoji|length|startsWith|endsWith|includes)\(/;

/**
 * True only when the schema named here is defined in this file and every
 * value in it is unconstrained text. Anything else -- a number, an enum, a
 * format, or a schema defined elsewhere -- keeps the benefit of the doubt.
 */
function schemaAcceptsAnyText(parsed: ParsedFile, name: string): boolean {
  let definition: Node | undefined;
  walk(parsed.program, (node) => {
    if (definition || node.type !== "VariableDeclarator") return;
    const id = node.id as Node | undefined;
    if (id?.type === "Identifier" && id.name === name && node.init) definition = node.init as Node;
  });
  if (!definition) return false;

  const text = textOf(parsed, definition);
  if (CONSTRAINS.test(text)) return false;

  const kinds = [...text.matchAll(/\bz\.(\w+)\(/g)].map((m) => m[1]!).filter((k) => !STRUCTURE.has(k));
  return kinds.length > 0 && kinds.every((k) => FREE_TEXT.has(k));
}

function sanitizerKindOf(init: Node, parsed: ParsedFile): Sanitizer["kind"] | undefined {
  if (init.type !== "CallExpression" && init.type !== "AwaitExpression") return undefined;

  const call = init.type === "AwaitExpression" ? (init.argument as Node) : init;
  if (!call || call.type !== "CallExpression") return undefined;

  const name = dottedName(call.callee) ?? "";

  if (/^(?:Number|parseInt|parseFloat)$/.test(name)) return "numeric-coercion";
  if (/\.(?:safeParse|parse)$/.test(name)) {
    const schema = name.split(".").slice(-2, -1)[0] ?? "";
    return schemaAcceptsAnyText(parsed, schema) ? undefined : "schema-validation";
  }
  if (/(?:^|\.)(?:normalize|resolve|basename)$/.test(name)) return "path-normalization";
  if (/(?:^|\.)(?:escape\w*|sanitize\w*)$/i.test(name)) return "escaping";
  return undefined;
}

/**
 * Is the command actually assembled from values, or passed safely?
 *
 * `spawnSync("git", ["ls-files"])` hands the program its arguments as separate
 * values; no shell parses them, so nothing a value contains can become an
 * instruction. `execSync(`git ${branch}`)` builds one string for a shell to
 * interpret, which is the dangerous form.
 *
 * Flagging both means flagging the correct pattern -- which this analyser did
 * to its own source, telling the author that code "pasting values into text"
 * was pasting nothing. A warning on correct code teaches people to ignore
 * warnings, so the distinction has to be made here.
 */
function isCommandBuilt(args: Node[]): boolean {
  const command = args[0];
  if (!command) return false;

  // An explicit `shell: true` re-introduces a shell even for the array forms.
  const forcesShell = args.slice(1).some((arg) =>
    arg.type === "ObjectExpression" &&
    ((arg.properties ?? []) as Node[]).some((property) => {
      const key = property.key as Node | undefined;
      const value = property.value as Node | undefined;
      return (
        key?.type === "Identifier" &&
        key.name === "shell" &&
        value?.type === "Literal" &&
        value.value === true
      );
    })
  );
  if (forcesShell) return true;

  // Built by interpolation.
  if (command.type === "TemplateLiteral") {
    return ((command.expressions ?? []) as Node[]).length > 0;
  }
  // Built by concatenation, where at least one side is not a fixed string.
  if (command.type === "BinaryExpression" && command.operator === "+") {
    return !isStringLiteral(command.left) || !isStringLiteral(command.right);
  }
  return false;
}

/**
 * The names a template prints without escaping.
 *
 * Every engine has a safe way to print (which turns `<script>` into harmless
 * text) and a raw way that does not. Only the raw way is dangerous, so only
 * names printed raw are collected. Names are the top-level ones the route
 * passes in: `<%- output.searchTerm %>` is the `output` the route provided.
 */
function rawNames(path: string, content: string): Set<string> {
  const names = new Set<string>();
  const add = (re: RegExp) => {
    for (const m of content.matchAll(re)) if (m[1]) names.add(m[1]);
  };
  const id = "([A-Za-z_$][\\w$]*)";

  if (/\.ejs$/i.test(path)) add(new RegExp(`<%-\\s*${id}`, "g"));
  if (/\.(?:hbs|handlebars)$/i.test(path)) add(new RegExp(`\\{\\{\\{\\s*${id}`, "g"));
  if (/\.pug$/i.test(path)) {
    add(new RegExp(`!\\{\\s*${id}`, "g"));
    add(new RegExp(`^\\s*[\\w.#-]*!=\\s*${id}`, "gm"));
  }
  if (/\.(?:njk|swig|html)$/i.test(path)) {
    // Nunjucks, Swig, and Jinja-style engines escape by default...
    add(new RegExp(`\\{\\{\\s*${id}[^}]*\\|\\s*safe\\b`, "g"));
    // ...unless escaping is switched off for the file.
    if (/\{%\s*autoescape\s+(?:false|off)\b/.test(content)) add(new RegExp(`\\{\\{\\s*${id}`, "g"));
  }
  return names;
}

/** The single template a view name refers to, or none when it is missing or ambiguous. */
function templateFor(view: string, views: Map<string, string>): [string, string] | undefined {
  const wanted = view.replace(/^\/+/, "");
  const hasExtension = /\.[a-z]+$/i.test(wanted);
  const matches = [...views].filter(([path]) => {
    const bare = hasExtension ? path : path.replace(/\.[a-z]+$/i, "");
    return bare === wanted || bare.endsWith(`/${wanted}`);
  });
  return matches.length === 1 ? matches[0] : undefined;
}

/**
 * `res.render("app/products", { output })` is dangerous only if the template
 * prints something the route passed in *raw*. The operation is the render
 * call; its operands are just the values handed to raw-printed names, so a
 * visitor's value passed to a name the template escapes is not reported.
 */
function renderSink(
  parsed: ParsedFile,
  node: Node,
  name: string,
  args: Node[],
  views: Map<string, string>,
): Sink | undefined {
  if (!/^(?:res|reply|response|ctx)\.render$/.test(name) || !isStringLiteral(args[0])) return undefined;
  const template = templateFor(String(args[0].value), views);
  if (!template) return undefined;

  const raw = rawNames(template[0], template[1]);
  if (raw.size === 0) return undefined;

  const locals = args[1];
  let values: Node[] = [];
  if (locals?.type === "ObjectExpression") {
    for (const property of (locals.properties ?? []) as Node[]) {
      const key = property.key as Node | undefined;
      const keyName = key?.type === "Identifier" ? String(key.name) : isStringLiteral(key) ? String(key.value) : "";
      if (raw.has(keyName) && property.value) values.push(property.value as Node);
    }
  } else if (locals) {
    // `res.render("page", data)`: which names it holds is not visible here.
    values = [locals];
  }
  if (values.length === 0) return undefined;

  return {
    id: `${parsed.path}:sink:${node.start}`,
    kind: "html",
    // Only the values that are printed raw, so an inline input matches only
    // when it is one of them.
    expression: values.map((v) => textOf(parsed, v)).join(" , ").replace(/\s+/g, " ").slice(0, 200),
    operands: values.flatMap((v) => identifiersIn(v)),
    location: locationOf(parsed, node),
    inherentlySafe: false,
  };
}

function sinkFor(
  parsed: ParsedFile,
  node: Node,
  parents: Node[],
  views: Map<string, string> = new Map(),
): Sink | undefined {
  const make = (kind: SinkKind, operands: string[], inherentlySafe = false): Sink => ({
    id: `${parsed.path}:sink:${node.start}`,
    kind,
    expression: textOf(parsed, node).replace(/\s+/g, " ").slice(0, 200),
    operands,
    location: locationOf(parsed, node),
    inherentlySafe,
  });

  /**
   * A template literal carrying a SQL statement.
   *
   * Safety is decided structurally: if this template is the quasi of a tagged
   * template whose tag is a query builder, every interpolation is sent as a
   * parameter and the statement cannot be altered. No escaping or formatting
   * can disguise one case as the other, which text matching could not promise.
   */
  if (node.type === "TemplateLiteral") {
    const expressions = (node.expressions ?? []) as Node[];
    if (expressions.length === 0) return undefined;
    if (!SQL_STATEMENT.test(quasiText(node))) return undefined;

    const parent = parents[0];
    const tagged = parent?.type === "TaggedTemplateExpression" && parent.quasi === node;
    const safe = tagged && SAFE_TAG.test(dottedName(parent.tag) ?? "");

    return make("sql", expressions.flatMap((e) => identifiersIn(e)), safe);
  }

  /**
   * A query assembled with `+`: `"SELECT ... WHERE login='" + name + "'"`.
   * Judged once, at the outermost `+`, from the fixed text of all its parts --
   * the statement is only recognisable when the pieces are read together.
   */
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const parent = parents[0];
    if (parent?.type === "BinaryExpression" && parent.operator === "+") return undefined;

    const parts: Node[] = [];
    const flatten = (n: Node): void => {
      if (n.type === "BinaryExpression" && n.operator === "+") {
        flatten(n.left as Node);
        flatten(n.right as Node);
      } else parts.push(n);
    };
    flatten(node);

    const fixed = parts.filter((p) => isStringLiteral(p)).map((p) => String(p.value)).join("");
    const moving = parts.filter((p) => !isStringLiteral(p));
    if (moving.length === 0 || !SQL_STATEMENT.test(fixed)) return undefined;
    return make("sql", moving.flatMap((p) => identifiersIn(p)));
  }

  if (node.type === "JSXAttribute") {
    const name = (node.name as { name?: string } | undefined)?.name;
    if (name === "dangerouslySetInnerHTML") {
      return make("html", identifiersIn(node));
    }
    return undefined;
  }

  if (node.type !== "CallExpression") return undefined;

  const name = dottedName(node.callee) ?? "";
  const args = (node.arguments ?? []) as Node[];
  const operands = args.flatMap((a) => identifiersIn(a));

  if (SHELL.test(name)) {
    return isCommandBuilt(args) ? make("shell", operands) : undefined;
  }
  if (DYNAMIC_CODE.test(name)) return make("dynamic-code", operands);

  {
    const parts = name.split(".");
    const method = parts.at(-1) ?? "";
    const owners = parts.slice(0, -1);
    const firstArg = args[0];
    const isCallback = firstArg && /Function|ArrowFunctionExpression/.test(firstArg.type);
    if (owners.length > 0 && ORM_METHOD.test(method) && owners.some((p) => MODEL_OWNER.test(p)) && !isCallback) {
      return make("sql", operands, true);
    }
  }

  const rendered = renderSink(parsed, node, name, args, views);
  if (rendered) return rendered;

  /**
   * `res.send(`<h1>${q}</h1>`)` -- markup assembled in a plain template and
   * sent as the page. Recognised only when the fixed text contains a tag, so
   * a JSON or text reply is not mistaken for a page.
   */
  if (/^(?:res|reply|response)\.(?:send|write|end)$/.test(name) && args[0]?.type === "TemplateLiteral") {
    const body = args[0];
    if (((body.expressions ?? []) as Node[]).length > 0 && /<[a-z!]/i.test(quasiText(body))) {
      return make("html", identifiersIn(body));
    }
  }

  /**
   * `c.html(...)` sends its argument to the browser as markup. A plain
   * template pastes values in as-is; Hono's `html` tagged template escapes
   * them, so only the untagged form is dangerous. A fixed string cannot be
   * steered at all.
   */
  if (/^(?:c|ctx|context)\.html$/.test(name) && args[0]) {
    const body = args[0];
    if (isStringLiteral(body)) return undefined;
    if (body.type === "TemplateLiteral" && ((body.expressions ?? []) as Node[]).length === 0) return undefined;
    const escaped = body.type === "TaggedTemplateExpression" && dottedName(body.tag) === "html";
    return make("html", identifiersIn(body), escaped);
  }
  /**
   * Only the first argument -- the path -- decides which file is touched.
   * Counting every argument reported `writeFile("uploads/fixed.bin", data)`
   * as steerable because of what was written, not where.
   */
  if (FILESYSTEM.test(name) || BUN_FILE.test(name)) {
    return make("filesystem", args[0] ? identifiersIn(args[0]) : []);
  }
  if (/\.redirect$/.test(name)) return make("redirect", operands);

  // Only an outbound request whose destination is computed is interesting; a
  // hardcoded URL cannot be steered.
  if (name === "fetch" && args[0] && !isStringLiteral(args[0])) {
    return make("outbound-request", identifiersIn(args[0]));
  }
  return undefined;
}

/**
 * Sinks in a single file, for the pattern rules.
 *
 * The oracle reports sinks it can prove untrusted input reaches. The rules are
 * the safety net for the ones it cannot prove -- but both must agree on what a
 * sink *is*, or the net reintroduces exactly the false positives the parser
 * removed. One detection, two consumers.
 */
export function findSinksInFile(file: { path: string; content: string }): Sink[] {
  const parsed = parseFile(file);
  if (!parsed) return [];

  const doors = findDoors(parsed);
  const inventory: Inventory = {
    doors,
    sources: [],
    sinks: [],
    sanitizers: [],
    assignments: [],
  };
  collect(parsed, doors, inventory);
  return inventory.sinks;
}
