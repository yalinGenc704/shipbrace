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
  Door,
  Inventory,
  Sanitizer,
  Sink,
  SinkKind,
  SourceKind,
  StoreAccess,
} from "./inventory.ts";
import { visitorInputChecker } from "./oracle.ts";
import { modelFields } from "./schemas.ts";

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
const MODEL_OWNER = /^(?:db|prisma|models?|repo|repository|knex)$|^[A-Z]|(?:Col|Collection|Model|Repo|Repository)$/;

/** Query methods whose filter is a MongoDB-style object. */
const MONGO_METHOD =
  /^(?:find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|countDocuments|count|exists)$/;

const SHELL = /^(?:execSync|exec|execFile|execFileSync|spawn|spawnSync)$/;
const FILESYSTEM =
  /(?:^|\.)(?:readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|rm|rmSync|createReadStream|createWriteStream|open)$/;
/** Turning text into running code. */
const DYNAMIC_CODE = /^(?:eval|vm\.runIn(?:New|This)?Context|vm\.compileFunction)$/;

/**
 * Decoders that rebuild running code from the text they are given, so whoever
 * wrote the text chooses what runs: node-serialize's `unserialize` (only when
 * imported from node-serialize -- PHP-format `unserialize` libraries build
 * plain values), js-yaml's `unsafeLoad`, funcster's `deepDeserialize`.
 * js-yaml's `load` counts only with a full schema written in. In js-yaml 3 a
 * plain `load` was already unsafe; that version is not told apart here, so
 * it is missed rather than guessed.
 */
const UNSAFE_DECODER = /(?:^|\.)(?:unsafeLoad|deepDeserialize)$/;
const UNSERIALIZE = /(?:^|\.)unserialize$/;
const YAML_LOAD = /(?:^|\.)(?:load|loadAll)$/;

function fullSchema(options: Node | undefined): boolean {
  if (options?.type !== "ObjectExpression") return false;
  return ((options.properties ?? []) as Node[]).some((prop) => {
    const key = (prop.key as Node | undefined)?.name;
    return key === "schema" && (dottedName(prop.value as Node) ?? "").endsWith("FULL_SCHEMA");
  });
}

/**
 * libxmljs (and libxmljs2) parse calls. They leave outside references alone
 * unless told otherwise, so only a call that switches them on is an operation
 * at all; xml2js, fast-xml-parser and xmldom never fetch them.
 */
const XML_PARSE = /(?:^|\.)(?:parseXml|parseXmlString|parseXmlAsync)$/;

/** True for an options object with `noent` or `dtdload` set to `true` (or 1) written out. */
function expandsEntities(options: Node | undefined): boolean {
  if (options?.type !== "ObjectExpression") return false;
  return ((options.properties ?? []) as Node[]).some((prop) => {
    const key = (prop.key as Node | undefined)?.name ?? (prop.key as Node | undefined)?.value;
    const value = prop.value as Node | undefined;
    return /^(?:noent|dtdload)$/.test(String(key)) && (value?.value === true || value?.value === 1);
  });
}

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

/**
 * `sql.begin(async (tx) => { await tx\`...${id}\` })`: postgres.js hands a
 * transaction a tag that parameterises exactly like `sql`. Recognised when the
 * tag is a parameter of a function passed to `begin`, `transaction`,
 * `savepoint` or `reserve` on a query client.
 */
function isTransactionTag(tag: string, parents: Node[]): boolean {
  if (!/^\w+$/.test(tag)) return false;
  for (let i = 0; i < parents.length; i++) {
    const fn = parents[i]!;
    if (!/^(?:ArrowFunctionExpression|FunctionExpression)$/.test(fn.type)) continue;
    const params = ((fn.params ?? []) as Node[]).map((p) => (p.type === "Identifier" ? String(p.name) : ""));
    if (!params.includes(tag)) continue;
    const call = parents[i + 1];
    const callee = call?.type === "CallExpression" ? dottedName(call.callee) ?? "" : "";
    const [owner, method] = [callee.split(".").slice(0, -1).join("."), callee.split(".").pop() ?? ""];
    return /^(?:begin|transaction|savepoint|reserve)$/.test(method) && (SAFE_TAG.test(owner) || isTransactionTag(owner, parents.slice(i + 1)));
  }
  return false;
}

/**
 * A query's text starts with its statement. Documentation that mentions one
 * mid-paragraph -- a README template saying "use query`SELECT ... ${value}`
 * from server/src/mysql.ts" -- is prose, not a query.
 */
const STATEMENT_START = /^\s*\(?\s*(?:SELECT|INSERT|UPDATE|DELETE|WITH|REPLACE|EXPLAIN|SET|BEGIN|MERGE|CALL)\b/i;
/** Leading SQL comments (`/* ... *\/`, `-- ...`) before the statement itself. */
const LEADING_COMMENTS = /^(?:\s*(?:\/\*[\s\S]*?\*\/|--[^\n]*(?:\n|$)))+/;
const startsAQuery = (text: string): boolean => STATEMENT_START.test(text.replace(LEADING_COMMENTS, ""));

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
  addStoredSources(inventory);
  addMassAssignment(inventory, snapshot);
  return inventory;
}

/**
 * Mass assignment: a model write that saves a whole object (`User.create(x)`,
 * `{ ...x }`) into a table that has a field a visitor must not choose -- a
 * role, an admin flag, an owner. Recorded as an operation whose value is the
 * whole object; the oracle then decides whether the visitor's whole request
 * reaches it. A table whose fields cannot be found gets nothing: whether it
 * matters depends on fields nobody can see.
 */
const position = (id: string): number => Number(id.split(":").pop()) || 0;

function addMassAssignment(inventory: Inventory, snapshot: RepoSnapshot): void {
  const writes = (inventory.stores ?? []).filter(
    (s) => s.mode === "write" && s.model && s.written?.some((w) => w.column === "*"),
  );
  if (writes.length === 0) return;
  const models = modelFields(snapshot);

  const assignments = inventory.assignments;
  /** Follows plain copies back from `name`, in the write's own scope, to the whole request. */
  /**
   * Follows plain copies back from `name`, in the write's own scope, to the
   * whole request. Returns the names on the way (with "request" last), or
   * undefined when the chain ends anywhere else.
   */
  const copiesOfRequest = (
    name: string,
    before: number,
    doorId: string | undefined,
    path: string,
    depth = 0,
  ): string[] | undefined => {
    if (depth > 8) return undefined;
    const last = assignments
      .filter((a) => a.target === name && a.doorId === doorId && a.location.path === path && position(a.id) < before)
      .sort((a, b) => position(b.id) - position(a.id))[0];
    if (!last) return undefined;
    if (last.wholeRequest) return [name, "request"];
    const rest = last.copyOf ? copiesOfRequest(last.copyOf, position(last.id), doorId, path, depth + 1) : undefined;
    return rest ? [name, ...rest] : undefined;
  };
  const doors = new Map(inventory.doors.map((d) => [d.id, d]));

  for (const write of writes) {
    const sensitive = models.get(write.store)?.sensitive ?? [];
    for (const value of write.written!) {
      if (value.column !== "*") continue;
      const at = position(write.id);
      const chain = value.wholeRequest
        ? ["request"]
        : value.copyOf !== undefined
        ? copiesOfRequest(value.copyOf, at, write.doorId, write.location.path)
        : undefined;
      if (!chain) continue;
      // Checked or trimmed on the way -- by a schema, a validator, `delete
      // form.role`, or middleware that replaces req.body -- so the fields that
      // arrive may be only the allowed ones. Errs to silence.
      if (inventory.requestBodyReplaced) continue;
      const checkedFirst = (inventory.requestChecks ?? []).some((c) =>
        chain.includes(c.subject) && c.path === write.location.path && c.doorId === write.doorId && c.at < at
      );
      if (checkedFirst) continue;
      // An administrator's own form often sets a role on purpose.
      const door = write.doorId ? doors.get(write.doorId) : undefined;
      if (door?.guards.some((g) => /admin/i.test(g))) continue;
      const open = sensitive.filter((field) => !(value.overridden ?? []).includes(field));
      if (open.length === 0) continue;
      inventory.sinks.push({
        id: write.id.replace(":store:", ":sink:"),
        kind: "mass-assignment",
        expression: write.expression,
        operands: value.names,
        location: write.location,
        inherentlySafe: false,
        ...(write.doorId ? { doorId: write.doorId } : {}),
        fields: open,
      });
      break;
    }
  }
}

/**
 * Stored data: a column a visitor's input is saved into is itself an input,
 * everywhere it is read back. Both halves must be shown by the code -- a
 * value a visitor sends, saved into a named column with nothing checking it
 * first, and a read of the same table that selects that column -- before the
 * read counts. Values that only pick which row to change (`WHERE id = ?`,
 * Prisma's `where`) are not saved and do not count.
 */
function addStoredSources(inventory: Inventory): void {
  const stores = inventory.stores ?? [];
  if (!stores.some((s) => s.mode === "write")) return;

  const savedByVisitor = visitorInputChecker(inventory);
  const tables = new Map<string, VisitorColumns>();
  const table = (store: string): VisitorColumns => {
    let t = tables.get(store);
    if (!t) tables.set(store, (t = { named: new Set(), whole: false, appSets: undefined, known: new Set() }));
    return t;
  };
  for (const write of stores) {
    if (write.mode !== "write") continue;
    const t = table(write.store);
    for (const column of write.touches ?? []) t.known.add(column);
    for (const { column, except } of savedByVisitor(write)) {
      if (column !== "*") {
        t.named.add(column);
        continue;
      }
      // A spread of the request saves every field except those set after it.
      // Across several such writes, only fields the app sets in all of them
      // are safe from the visitor.
      t.whole = true;
      t.appSets = t.appSets ? new Set(except.filter((c) => t.appSets!.has(c))) : new Set(except);
    }
  }

  for (const read of stores) {
    const t = tables.get(read.store);
    if (read.mode !== "read" || !read.binding || !t || (!t.whole && t.named.size === 0)) continue;
    if (!readsOnlyVisitorText(read.columns ?? ["*"], t)) continue;
    inventory.sources.push({
      id: read.id.replace(":store:", ":src:"),
      kind: "stored-data",
      expression: read.expression,
      binding: read.binding,
      location: read.location,
      ...(read.doorId ? { doorId: read.doorId } : {}),
    });
  }
}

interface VisitorColumns {
  /** Columns a visitor's value is saved into by name. */
  named: Set<string>;
  /** True when a whole request is saved into the table. */
  whole: boolean;
  /** With `whole`: columns the app always sets itself after the spread. */
  appSets: Set<string> | undefined;
  /** Every column any write names. */
  known: Set<string>;
}

/** Ids, foreign keys and timestamps: set by the database or the app, never text worth showing. */
const BOOKKEEPING = /^(?:id|created|updated|\w+_at|\w+At|created_on|updated_on)$/;

/**
 * True when what a read returns is visitor text and nothing else that could
 * be text. The result is followed as one value, so a read that also returns
 * columns only the app writes cannot say which of them reaches the page;
 * that case stays silent rather than guessing.
 */
function readsOnlyVisitorText(selected: string[], t: VisitorColumns): boolean {
  const fromVisitor = (c: string): boolean => t.named.has(c) || (t.whole && !(t.appSets?.has(c) ?? false));
  const all = selected.includes("*");
  // Everything, from a table the whole request goes into, with nothing set by
  // the app: all of it is visitor text.
  if (all && t.whole && (t.appSets?.size ?? 0) === 0) return true;
  if (all && t.known.has("*")) return false;
  const returned = all ? [...t.known] : selected;
  const visitorColumns = returned.filter(fromVisitor);
  const others = returned.filter((c) => !fromVisitor(c) && !BOOKKEEPING.test(c));
  return visitorColumns.length > 0 && others.length === 0;
}

const SQL_INSERT = /\bINSERT\s+(?:OR\s+\w+\s+)?INTO\s+["`'[]?(\w+)["`'\]]?\s*(?:\(([^)]*)\))?\s*VALUES\s*\(/i;
const SQL_UPDATE = /\bUPDATE\s+["`'[]?(\w+)["`'\]]?\s+SET\b/i;
const SQL_READ = /\bSELECT\b([\s\S]*?)\bFROM\s+["`'[]?(\w+)/i;
/**
 * `?`, `$2`, or an interpolation slot. quasiText marks slots with U+0000; it
 * is swapped for a private-use character first so the pattern stays printable.
 */
const SLOT = "\uE000";
const PLACEHOLDER = /\?|\$(\d+)|\uE000/g;
const MODEL_CREATE = /^(?:create|createMany|bulkCreate|insert|insertOne|insertMany)$/;
const MODEL_UPDATE = /^(?:update|updateOne|updateMany|upsert|findOneAndUpdate|findByIdAndUpdate)$/;
const MODEL_READ = /^(?:find|findOne|findAll|findMany|findFirst|findUnique|findById|findByPk)$/;
const GENERIC_OWNER = /^(?:db|prisma|models?|repo|repository|knex|this)$/;
/** Expression shapes a query result passes through on its way to a variable. */
const CHAIN = /^(?:CallExpression|MemberExpression|StaticMemberExpression|ComputedMemberExpression|AwaitExpression|TaggedTemplateExpression|ChainExpression|ParenthesizedExpression)$/;

const storeName = (raw: string): string => raw.toLowerCase().replace(/s$/, "");
const columnName = (raw: string): string =>
  raw.trim().replace(/^["`'[]|["`'\]]$/g, "").split(".").pop()!.toLowerCase();

/** Splits on commas that are not inside brackets: `a, f(b, c), d`. */
function topLevelParts(text: string, offset: number): Array<{ text: string; at: number }> {
  const parts: Array<{ text: string; at: number }> = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i <= text.length; i++) {
    const ch = text[i];
    if (ch === "(") depth++;
    else if (ch === ")") depth--;
    if ((ch === "," && depth === 0) || i === text.length) {
      parts.push({ text: text.slice(start, i), at: offset + start });
      start = i + 1;
    }
  }
  return parts;
}

/**
 * Which values a SQL write saves into which columns. Each placeholder is
 * matched to the value bound to it -- positionally for `?`, by number for
 * `$2`, and in order for a template's `${...}` -- and only placeholders in
 * the VALUES list or a `SET col = ?` count. Anything it cannot line up is
 * left out, which errs towards silence.
 */
function sqlWrittenValues(
  text: string,
  bound: Node[],
  interpolated: Node[],
): { values: StoreValue[]; touches: string[] } | undefined {
  const slots: Array<{ at: number; node: Node | undefined }> = [];
  let question = 0;
  let slot = 0;
  for (const match of text.replaceAll("\u0000", SLOT).matchAll(PLACEHOLDER)) {
    const node = match[0] === "?" ? bound[question++]
      : match[0] === SLOT ? interpolated[slot++]
      : bound[Number(match[1]) - 1];
    slots.push({ at: match.index!, node });
  }
  const valuesIn = (from: number, to: number): Node[] =>
    slots.filter((s) => s.at >= from && s.at < to && s.node).map((s) => s.node!);

  const insert = SQL_INSERT.exec(text);
  if (insert) {
    const columns = insert[2] ? insert[2].split(",").map(columnName) : [];
    const open = insert.index + insert[0].length;
    let depth = 1;
    let close = open;
    while (close < text.length && depth > 0) {
      if (text[close] === "(") depth++;
      else if (text[close] === ")") depth--;
      close++;
    }
    const values = topLevelParts(text.slice(open, close - 1), open).flatMap((part, i) =>
      valuesIn(part.at, part.at + part.text.length).map((node) => ({ column: columns[i] ?? "*", node }))
    );
    return { values, touches: columns.length > 0 ? columns : ["*"] };
  }

  const update = SQL_UPDATE.exec(text);
  if (update) {
    const setFrom = update.index + update[0].length;
    const where = /\bWHERE\b/i.exec(text.slice(setFrom));
    const setText = text.slice(setFrom, where ? setFrom + where.index : text.length);
    const parts = topLevelParts(setText, setFrom).filter((part) => part.text.includes("="));
    const values = parts.flatMap((part) => {
      const eq = part.text.indexOf("=");
      const column = columnName(part.text.slice(0, eq));
      return valuesIn(part.at + eq, part.at + part.text.length).map((node) => ({ column, node }));
    });
    return { values, touches: parts.map((part) => columnName(part.text.slice(0, part.text.indexOf("=")))) };
  }
  return undefined;
}

/** The columns a SELECT returns: `*`, or the names it lists. */
function selectedColumns(list: string): string[] {
  return topLevelParts(list.replaceAll("\u0000", ""), 0).map((part) => {
    const text = part.text.trim();
    if (/(?:^|\.)\*$/.test(text)) return "*";
    // `count(*) AS n` returns a number, not anything a visitor typed.
    if (/^\w+\s*\(/.test(text)) return "";
    return columnName(text.split(/\s+(?:as\s+)?/i)[0] ?? "");
  }).filter(Boolean);
}

/** Properties of an object literal, by name. */
function propertiesOf(node: Node | undefined): Map<string, Node> {
  const found = new Map<string, Node>();
  if (node?.type !== "ObjectExpression") return found;
  for (const prop of (node.properties ?? []) as Node[]) {
    if (prop.type !== "Property" && prop.type !== "ObjectProperty") continue;
    const key = prop.key as Node | undefined;
    const name = key?.type === "Identifier" ? key.name : isStringLiteral(key) ? key.value : undefined;
    if (name !== undefined) found.set(String(name).toLowerCase(), prop.value as Node);
  }
  return found;
}

/** A saved document: one value per named field, or the whole thing when it is not written out. */
function documentValues(doc: Node | undefined): StoreValue[] {
  if (!doc) return [];
  const props = propertiesOf(doc);
  if (doc.type === "ObjectExpression") {
    const all = (doc.properties ?? []) as Node[];
    // `{ ...req.body, role: "member" }`: the spread saves whatever it holds,
    // except the keys written after it, which replace what it brought.
    const spreads = all.flatMap((prop, i): StoreValue[] =>
      prop.type === "SpreadElement"
        ? [{
          column: "*",
          node: prop.argument as Node,
          overridden: keysAfter(all.slice(i + 1)),
        }]
        : []
    );
    return [...[...props.entries()].map(([column, node]) => ({ column, node })), ...spreads];
  }
  if (doc.type === "ArrayExpression") {
    return ((doc.elements ?? []) as Node[]).flatMap((e) => documentValues(e));
  }
  return [{ column: "*", node: doc }];
}

/**
 * The values a model method saves. Only the document or `data` counts, never
 * the filter that picks which record: `prisma.post.update({ where, data })`,
 * Mongoose's `updateOne(filter, update)`, Sequelize's `update(values, { where })`.
 */
function modelWrittenValues(method: string, args: Node[]): StoreValue[] {
  const first = args[0];
  const firstProps = propertiesOf(first);
  if (firstProps.has("data") || firstProps.has("where")) {
    return ["data", "create", "update"].flatMap((key) => documentValues(firstProps.get(key)));
  }
  if (MODEL_CREATE.test(method)) return documentValues(first);
  if (args.length >= 2 && propertiesOf(args[1]).has("where")) return documentValues(first);
  return documentValues(args[1]);
}

interface StoreValue {
  column: string;
  node: Node;
  /** For a spread: keys set after it in the same object, which it cannot supply. */
  overridden?: string[];
}

function keysAfter(props: Node[]): string[] {
  return [...propertiesOf({ type: "ObjectExpression", properties: props, start: 0, end: 0 } as Node).keys()];
}

/**
 * A read or write of a named table or collection at this node, if any.
 * SQL is recognised in a string or template passed to a call (or tagged), so
 * prose that mentions "update ... set" is not mistaken for a statement.
 */
function storeAccessFor(parsed: ParsedFile, node: Node, parents: Node[]): StoreAccess | undefined {
  let text: string | undefined;
  if (node.type === "TemplateLiteral") text = quasiText(node);
  else if (isStringLiteral(node)) text = String(node.value);

  // The call chain the statement sits in: `db.prepare("...").bind(a).run()`.
  const chain: Node[] = [];
  for (const parent of parents) {
    if (!CHAIN.test(parent.type)) break;
    chain.push(parent);
  }
  const outer = chain.at(-1) ?? node;

  const make = (store: string, mode: StoreAccess["mode"], extra: Partial<StoreAccess>): StoreAccess => {
    const binding = mode === "read" ? bindingFor(parents) : undefined;
    return {
      id: `${parsed.path}:store:${node.start}`,
      store: storeName(store),
      mode,
      ...(binding ? { binding } : {}),
      expression: textOf(parsed, outer).replace(/\s+/g, " ").slice(0, 160),
      range: [outer.start, outer.end],
      location: locationOf(parsed, node),
      ...extra,
    };
  };
  const toWritten = (values: StoreValue[]): NonNullable<StoreAccess["written"]> =>
    values.map(({ column, node: value, overridden }) => ({
      column,
      names: identifiersIn(value),
      range: [value.start, value.end] as [number, number],
      ...(overridden ? { overridden } : {}),
      ...copyShape(value),
    }));

  if (text !== undefined) {
    const inCall = parents[0]?.type === "CallExpression" ||
      (parents[0]?.type === "TaggedTemplateExpression" && parents[0].quasi === node);
    if (!inCall) return undefined;

    // Values bound to the statement, in order: the call's other arguments (an
    // array of them counts as the list), then those of `.bind(...)`/`.run(...)`.
    const bound = chain
      .filter((n) => n.type === "CallExpression")
      .flatMap((call) => {
        const args = ((call.arguments ?? []) as Node[]).filter((a) => a !== node);
        return args.length === 1 && args[0]!.type === "ArrayExpression"
          ? ((args[0]!.elements ?? []) as Node[])
          : args;
      });
    const interpolated = node.type === "TemplateLiteral" ? ((node.expressions ?? []) as Node[]) : [];

    const writes = sqlWrittenValues(text, bound, interpolated);
    const store = SQL_INSERT.exec(text)?.[1] ?? SQL_UPDATE.exec(text)?.[1];
    if (writes && store) return make(store, "write", { written: toWritten(writes.values), touches: writes.touches });

    const read = SQL_READ.exec(text);
    if (read) {
      const columns = selectedColumns(read[1]!);
      return columns.length > 0 ? make(read[2]!, "read", { columns }) : undefined;
    }
    return undefined;
  }

  if (node.type !== "CallExpression") return undefined;
  const parts = (dottedName(node.callee) ?? "").split(".");
  const method = parts.at(-1) ?? "";
  const owners = parts.slice(0, -1);
  if (owners.length === 0) return undefined;

  // `prisma.comment.create`, `db.Comment.create` -> the part after the client;
  // `Comment.create`, `CommentModel.find` -> the model itself.
  const last = owners.at(-1)!;
  const model = owners.length >= 2 && GENERIC_OWNER.test(owners[0]!) && !GENERIC_OWNER.test(last)
    ? last
    : /^[A-Z]/.test(last) || /(?:Col|Collection|Model)$/.test(last)
    ? last.replace(/(?:Col|Collection|Model)$/, "") || last
    : undefined;
  if (!model) return undefined;

  const args = (node.arguments ?? []) as Node[];
  if (MODEL_CREATE.test(method) || MODEL_UPDATE.test(method)) {
    const values = modelWrittenValues(method, args);
    return make(model, "write", { written: toWritten(values), touches: values.map((v) => v.column), model: true });
  }
  if (MODEL_READ.test(method)) return make(model, "read", { columns: ["*"] });
  return undefined;
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

    const inline = signInCheckedFirst(handler);
    if (inline) guards.add(inline);

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
      // Steps named before the handler (an upload, a body parser) do work of
      // their own, so such a route is never treated as answering only.
      ...(middleware.length === 0 && answersOnlyFixed(handler) ? { answersOnlyFixed: true } : {}),
    };
  });
}

/** The visitor's whole request: `req.body`, `req.query`... */
const WHOLE_REQUEST_READ = /^(?:req|request)\.(?:body|query)$/;
/** ...or a call with no arguments that returns it: `c.req.json()`, `request.formData()`. */
const WHOLE_REQUEST_CALL = /^(?:(?:c|ctx|context)\.req\.(?:json|parseBody|query)|(?:req|request)\.(?:json|formData))$/;

/**
 * Whether an expression is an exact copy of something: a plain name, or the
 * visitor's whole request. Anything else -- a call such as `schema.parse(x)`
 * or `pick(x, [...])`, a rebuilt object, a destructured field -- may have
 * dropped fields, so it is neither.
 */
function copyShape(expression: Node): { copyOf?: string; wholeRequest?: true } {
  const node = awaited(expression);
  if (!node) return {};
  if (node.type === "Identifier") return { copyOf: String(node.name) };
  if (node.type.endsWith("MemberExpression") && WHOLE_REQUEST_READ.test(dottedName(node) ?? "")) {
    return { wholeRequest: true };
  }
  const bare = node.type === "CallExpression" && ((node.arguments ?? []) as Node[]).length === 0;
  if (bare && WHOLE_REQUEST_CALL.test(dottedName(node.callee) ?? "")) return { wholeRequest: true };
  return {};
}

/** Calls that check or trim what they are given. */
const CHECKING_CALL = /(?:^|\.)(?:parse|safeParse|parseAsync|safeParseAsync|validate\w*|assert\w*|check\w*|sanitize\w*|strip\w*|clean\w*|filter\w*|omit|pick|is[A-Z]\w*)$/;

/**
 * What a check is about: "request" for the whole request itself, a name for
 * a plain variable, or nothing. `S.parse(req.body)`, `validate(form)`,
 * `delete form.role` all count.
 */
function requestCheckOf(node: Node): string | undefined {
  const subject = (arg: Node | undefined): string | undefined => {
    const shape = arg ? copyShape(arg) : {};
    return shape.wholeRequest ? "request" : shape.copyOf;
  };
  if (node.type === "CallExpression" && CHECKING_CALL.test(dottedName(node.callee) ?? "")) {
    for (const arg of (node.arguments ?? []) as Node[]) {
      const found = subject(arg);
      if (found) return found;
    }
  }
  if (node.type === "UnaryExpression" && node.operator === "delete") {
    const target = node.argument as Node | undefined;
    if (target?.type.endsWith("MemberExpression")) {
      const object = target.object as Node;
      return WHOLE_REQUEST_READ.test(dottedName(object) ?? "") ? "request" : subject(object);
    }
  }
  return undefined;
}

/** Unwraps `await x` to `x`. */
const awaited = (node: Node | undefined): Node | undefined =>
  node?.type === "AwaitExpression" ? (node.argument as Node | undefined) : node;

/** Calls whose name says they establish who is signed in. Not `getUser(id)`: that looks a record up. */
const SIGNED_IN_CALL =
  /^(?:isAuthenticated|isLoggedIn|isSignedIn|isAuthorized|authenticate|getSession|getServerSession|getCurrentUser|currentUser|requireUser|getAuth|auth|verifyToken|verifyJwt)$/;
/** Request inputs that pick a record; a lookup fed by one is not a sign-in check. */
const PICKS_A_RECORD = /(?:^|\.)(?:params?|query|queries|body)(?:\.|$)|(?:^|\.)req\.(?:param|query|json|parseBody)$/;

/**
 * True when an expression asks who is signed in: a read of the signed-in
 * user (`c.get("user")`, `req.user`), or a call whose name says it is a
 * sign-in check, or a lookup in a table of signed-in people
 * (`authenticatedUsers.get(token)`). A call fed by route, query or body
 * values looks a record up instead (`getAuthor(id)`), so it never counts.
 */
function asksWhoIsSignedIn(expression: Node): boolean {
  let asks = false;
  let picksRecord = false;
  walk(expression, (node) => {
    const name = node.type === "CallExpression" ? dottedName(node.callee) ?? "" : dottedName(node) ?? "";
    if (PICKS_A_RECORD.test(name)) picksRecord = true;
    if (isIdentityRead(node)) asks = true;
    else if (node.type === "CallExpression" && (SIGNED_IN_CALL.test(name.split(".").pop() ?? "") || /authenticated/i.test(name))) {
      asks = true;
    }
  });
  return asks && !picksRecord;
}

/** A branch that ends the request: `return ...`, `throw ...`, or a block ending in one. */
function leaves(branch: Node | undefined): boolean {
  if (!branch) return false;
  if (branch.type === "ReturnStatement" || branch.type === "ThrowStatement") return true;
  if (branch.type !== "BlockStatement") return false;
  const last = ((branch.body ?? []) as Node[]).at(-1);
  return last?.type === "ReturnStatement" || last?.type === "ThrowStatement";
}

/**
 * A sign-in check written at the top of the handler itself:
 *
 *   const user = c.get("user");
 *   if (!user) return c.json({ error: "Sign in" }, 401);
 *
 * Counted only when it is the handler's first real step -- before it, only
 * declarations that read the request or ask who is signed in -- and the
 * check leaves when nobody is. A check further down may come after the
 * route has already done something, so it is not counted.
 */
function signInCheckedFirst(handler: Node, depth = 0): string | undefined {
  if (!/^(?:ArrowFunctionExpression|FunctionExpression)$/.test(handler.type)) return undefined;
  const body = handler.body as Node | undefined;
  if (body?.type !== "BlockStatement") return undefined;

  // `void (async () => { ... })()` -- the whole handler wrapped in one
  // function that runs at once: its first steps are the handler's first steps.
  const only = (body.body ?? []) as Node[];
  if (only.length === 1 && only[0]!.type === "ExpressionStatement" && depth < 2) {
    let inner = only[0]!.expression as Node | undefined;
    if (inner?.type === "UnaryExpression" && inner.operator === "void") inner = inner.argument as Node;
    while (inner?.type === "ParenthesizedExpression") inner = inner.expression as Node;
    if (inner?.type === "CallExpression" && ((inner.arguments ?? []) as Node[]).length === 0) {
      let callee = inner.callee as Node | undefined;
      while (callee?.type === "ParenthesizedExpression") callee = callee.expression as Node;
      if (callee) return signInCheckedFirst(callee, depth + 1);
    }
  }

  const identities = new Set<string>();
  for (const statement of (body.body ?? []) as Node[]) {
    if (statement.type === "VariableDeclaration") {
      for (const declarator of (statement.declarations ?? []) as Node[]) {
        const init = awaited(declarator.init as Node | undefined);
        if (!init) continue;
        if (asksWhoIsSignedIn(init)) {
          for (const name of identifiersIn(declarator.id as Node)) identities.add(name);
          continue;
        }
        // Anything else that calls out may already do work; stop looking.
        let calls = false;
        walk(init, (n) => { if (n.type === "CallExpression") calls = true; });
        if (calls) return undefined;
      }
      continue;
    }
    if (statement.type !== "IfStatement" || !leaves(statement.consequent as Node)) return undefined;

    const test = statement.test as Node;
    const negated = test.type === "UnaryExpression" && test.operator === "!" ? (test.argument as Node) : undefined;
    // `if (user == null)`, `if (user === undefined)`
    const isNothing = (n: Node): boolean =>
      n.type === "NullLiteral" || (n.type === "Literal" && n.value === null) ||
      (n.type === "Identifier" && n.name === "undefined");
    const compared = test.type === "BinaryExpression" && (test.operator === "==" || test.operator === "===")
      ? [test.left as Node, test.right as Node]
      : [];
    const empty = compared.some(isNothing) ? compared.find((n) => !isNothing(n)) : undefined;
    const subject = negated ?? empty;
    if (!subject) return undefined;

    const root = identifiersIn(subject)[0];
    if (root && identities.has(root)) return root;
    if (asksWhoIsSignedIn(subject)) return dottedName(subject.type === "CallExpression" ? subject.callee : subject) ?? "signed-in check";
    return undefined;
  }
  return undefined;
}

/** Ways a handler can answer without reading or doing anything else. */
const ANSWER = /^(?:json|text|html|body|notFound|status|send|sendStatus|end|type)$/;

/**
 * True for an inline handler whose only uses of its own parameters are
 * called answer methods (`c.json`, `res.status(...).send`) and whose code names
 * nothing else -- no variables, no other calls, no `c.req`, no `next()`.
 * Anything it cannot read that plainly is false, so the route is still
 * reported.
 */
function answersOnlyFixed(handler: Node): boolean {
  if (!/^(?:ArrowFunctionExpression|FunctionExpression)$/.test(handler.type)) return false;
  const params = ((handler.params ?? []) as Node[]).map((p) => (p.type === "Identifier" ? String(p.name) : ""));
  if (params.some((p) => p === "")) return false;
  const body = handler.body as Node | undefined;
  if (!body) return false;

  let fixed = true;
  walk(body, (node, parents) => {
    if (!fixed) return;
    const parent = parents[0];
    if (/^(?:MemberExpression|StaticMemberExpression|ComputedMemberExpression)$/.test(node.type)) {
      // Only called answer methods: `c.json(...)`, not a read like `req.body`.
      const property = node.property as Node | undefined;
      const called = parent?.type === "CallExpression" && parent.callee === node;
      if (node.computed || !called || property?.type !== "Identifier" || !ANSWER.test(String(property.name))) fixed = false;
      return;
    }
    if (node.type !== "Identifier") return;
    // A property name or object key is not a reference to anything.
    if (parent && parent.type.endsWith("MemberExpression") && parent.property === node) return;
    if (parent && (parent.type === "Property" || parent.type === "ObjectProperty") && parent.key === node && !parent.computed) return;
    // A parameter may only be the thing an answer method is called on.
    const isObjectOfMember = parent && parent.type.endsWith("MemberExpression") && parent.object === node;
    if (!params.includes(String(node.name)) || !isObjectOfMember) fixed = false;
  });
  return fixed;
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
          ...copyShape(init),
          location: locationOf(parsed, node),
          ...doorId,
        });

        const kind = sanitizerKindOf(init, parsed);
        if (kind) {
          const protects = protectsOf(init);
          into.sanitizers.push({
            id: `${parsed.path}:san:${node.start}`,
            kind,
            ...(protects ? { protects } : {}),
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
          ...copyShape(right),
          location: locationOf(parsed, node),
          ...doorId,
        });
        const kind = sanitizerKindOf(right, parsed);
        if (kind) {
          const protects = protectsOf(right);
          into.sanitizers.push({
            id: `${parsed.path}:san:${node.start}`,
            kind,
            ...(protects ? { protects } : {}),
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

    // --- checks of a whole request, for mass assignment -------------------
    const checked = requestCheckOf(node);
    if (checked) {
      (into.requestChecks ??= []).push({ subject: checked, at: node.start, path: parsed.path, ...doorId });
    }
    if (node.type === "AssignmentExpression" && WHOLE_REQUEST_READ.test(dottedName(node.left) ?? "")) {
      into.requestBodyReplaced = true;
    }

    // --- tables and collections, for stored data -------------------------
    const store = storeAccessFor(parsed, node, parents);
    if (store) (into.stores ??= []).push({ ...store, ...doorId });

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

/**
 * What an escaping or path step protects, read from its name. Each only makes
 * a value safe for one kind of place: HTML escaping leaves `; rm -rf` and
 * `../` untouched, and a shell quote does nothing for a page. Names that do
 * not say which (`sanitize`, `escapeInput`) are credited everywhere.
 */
function protectsOf(init: Node): SinkKind[] | undefined {
  const call = init.type === "AwaitExpression" ? (init.argument as Node) : init;
  if (call?.type !== "CallExpression") return undefined;
  const name = dottedName(call.callee) ?? "";
  // Numbers and schema checks make a value safe everywhere.
  if (/^(?:Number|parseInt|parseFloat)$/.test(name) || /\.(?:safeParse|parse)$/.test(name)) return undefined;
  return protectsFor(name);
}

function protectsFor(name: string): SinkKind[] | undefined {
  const last = name.split(".").pop() ?? "";
  if (/^(?:escapeRegExp|escapeRegex|escapeStringRegexp)$/i.test(last)) return [];
  if (/sql|^escapeLiteral$|^escapeIdentifier$|^escapeId$/i.test(last) || /^(?:mysql|connection|pool|conn|db|SqlString)\.escape$/.test(name)) {
    return ["sql"];
  }
  // Only names that say "shell", and shell-quote's own `quote`; `escapeQuotes`
  // could be for anything, so it stays unlabelled.
  if (/shell/i.test(last) || last === "quote") return ["shell"];
  if (/filename|filenamify/i.test(last) || last === "basename") return ["filesystem"];
  if (/^(?:normalize|resolve)$/.test(last)) return ["filesystem"];
  if (
    /html|xss/i.test(last) || /^(?:DOMPurify|purify)\.sanitize$/.test(name) ||
    /^(?:_|lodash|validator|he|entities)\.(?:escape|encode)$/.test(name)
  ) {
    return ["html"];
  }
  return undefined;
}

/** True when `local` is bound by an import or require of `module` in this file. */
function importedFrom(parsed: ParsedFile, local: string, module: string): boolean {
  let found = false;
  walk(parsed.program, (node) => {
    if (found) return;
    if (node.type === "ImportDeclaration" && (node.source as Node | undefined)?.value === module) {
      found = ((node.specifiers ?? []) as Node[]).some((s) => (s.local as Node | undefined)?.name === local);
    }
    if (node.type === "VariableDeclarator") {
      const init = node.init as Node | undefined;
      const requires = init?.type === "CallExpression" && dottedName(init.callee) === "require" &&
        ((init.arguments ?? []) as Node[])[0]?.value === module;
      if (requires) found = identifiersIn(node.id as Node).includes(local);
    }
  });
  return found;
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
  // Shell quoting, safe for a command only (see protectsFor). A bare `quote`
  // counts only when it comes from shell-quote: a home-made one that wraps a
  // value in double quotes does not stop `$(...)`.
  if (/(?:^|\.)(?:shellQuote|shell[Ee]scape\w*|escapeShell\w*)$/.test(name)) return "escaping";
  if (/(?:^|\.)quote$/.test(name) && importedFrom(parsed, name.split(".")[0]!, "shell-quote")) return "escaping";
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

/**
 * MongoDB filters are objects, so a visitor who sends an object instead of a
 * string -- `{"$ne": null}` for a password -- changes what the query means:
 * "any user whose password is not empty". Two shapes are recognised:
 *
 *  - a filter value read straight from the request, unwrapped:
 *    `User.findOne({ name: req.body.name })`. Read inline only: once the value
 *    passes through a variable it may have been turned into a string on the
 *    way, and guessing would warn about correct code.
 *  - `$where`, which runs JavaScript inside the database, built from values.
 *
 * Sequelize also has `find`, but wraps its filter in `where:`; those are
 * left to the record-lookup path.
 */
function mongoFilterSink(parsed: ParsedFile, node: Node, method: string, filter: Node | undefined): Sink | undefined {
  if (!MONGO_METHOD.test(method) || filter?.type !== "ObjectExpression") return undefined;
  const properties = (filter.properties ?? []) as Node[];
  const keyOf = (p: Node) => {
    const key = p.key as Node | undefined;
    return key?.type === "Identifier" ? String(key.name) : isStringLiteral(key) ? String(key.value) : "";
  };
  if (properties.some((p) => keyOf(p) === "where")) return undefined;

  const raw: Node[] = [];
  const operands: string[] = [];
  for (const property of properties) {
    const value = property.value as Node | undefined;
    if (!value) continue;
    if (keyOf(property) === "$where") {
      if (value.type === "TemplateLiteral" || value.type === "BinaryExpression") {
        raw.push(value);
        operands.push(...identifiersIn(value));
      }
      continue;
    }
    // Only the value itself, read from the request with nothing around it.
    if (value.type === "MemberExpression" && /\breq\.(?:body|query|params)\b/.test(textOf(parsed, value))) {
      raw.push(value);
    }
  }
  if (raw.length === 0) return undefined;

  return {
    id: `${parsed.path}:sink:${node.start}`,
    kind: "nosql",
    expression: raw.map((v) => textOf(parsed, v)).join(" , ").replace(/\s+/g, " ").slice(0, 200),
    operands,
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
    if (!SQL_STATEMENT.test(quasiText(node)) || !startsAQuery(quasiText(node))) return undefined;

    const parent = parents[0];
    const tagged = parent?.type === "TaggedTemplateExpression" && parent.quasi === node;
    const tag = tagged ? dottedName(parent.tag) ?? "" : "";
    const safe = tagged && (SAFE_TAG.test(tag) || isTransactionTag(tag, parents));

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
    if (moving.length === 0 || !SQL_STATEMENT.test(fixed) || !startsAQuery(fixed)) return undefined;
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
  if (XML_PARSE.test(name) && expandsEntities(args[1])) {
    return make("xml-entities", args[0] ? identifiersIn(args[0]) : []);
  }
  if (DYNAMIC_CODE.test(name)) return make("dynamic-code", operands);
  const fromNodeSerialize = UNSERIALIZE.test(name) && importedFrom(parsed, name.split(".")[0]!, "node-serialize");
  if (fromNodeSerialize || UNSAFE_DECODER.test(name) || (YAML_LOAD.test(name) && fullSchema(args[1]))) {
    return make("unsafe-decoding", args[0] ? identifiersIn(args[0]) : []);
  }

  {
    const parts = name.split(".");
    const method = parts.at(-1) ?? "";
    const owners = parts.slice(0, -1);
    const firstArg = args[0];
    const isCallback = firstArg && /Function|ArrowFunctionExpression/.test(firstArg.type);
    if (owners.length > 0 && ORM_METHOD.test(method) && owners.some((p) => MODEL_OWNER.test(p)) && !isCallback) {
      const mongo = mongoFilterSink(parsed, node, method, firstArg);
      if (mongo) return mongo;
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
  if (name.endsWith('.redirect')) return make("redirect", operands);

  // Only an outbound request whose destination is computed is interesting; a
  // hardcoded URL cannot be steered, and neither can one whose public website
  // is fixed in the code with only the path filled in.
  if (name === "fetch" && args[0] && !isStringLiteral(args[0]) && !fixedPublicOrigin(args[0])) {
    return make("outbound-request", identifiersIn(args[0]));
  }
  return undefined;
}

/**
 * True when a URL's website is written out in full in the code -- a template
 * or `+` that begins with "https://api.github.com/" -- and that website is a
 * public one. A visitor's value can then only change the path on that site,
 * which is not a request forged to a place of their choosing.
 *
 * A fixed *internal* address stays a finding: steering the path on
 * `http://localhost:8080/` or `http://10.0.0.5/` still reaches private
 * services, which is what request forgery is about.
 */
const FIXED_ORIGIN = /^https?:\/\/([^/?#\s]+)[/?#]/i;
const INTERNAL_HOST =
  /^(?:localhost|.*\.(?:local|localhost|internal|lan)|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|0\.|\[|[^.]+$)/i;

function fixedPublicOrigin(node: Node): boolean {
  let lead: string | undefined;
  if (node.type === "TemplateLiteral") {
    const first = (node.quasis as Array<{ value?: { cooked?: string } }> | undefined)?.[0];
    lead = first?.value?.cooked;
  } else if (node.type === "BinaryExpression" && node.operator === "+") {
    let left = node.left as Node;
    while (left.type === "BinaryExpression" && left.operator === "+") left = left.left as Node;
    lead = isStringLiteral(left) ? left.value : undefined;
  }
  const host = lead?.match(FIXED_ORIGIN)?.[1]?.replace(/:\d+$/, "");
  return Boolean(host && !INTERNAL_HOST.test(host));
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
