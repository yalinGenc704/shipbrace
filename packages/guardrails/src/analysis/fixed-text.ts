import { contains, dottedName, walk, type Node, type ParsedFile } from "./ast.ts";

/**
 * Whether a value pasted into a query is fixed text: written in the code,
 * never anything a visitor can send.
 *
 * Code that runs a query over a list has to build one placeholder per item,
 * and the only way to do that is to paste text in:
 *
 *   `... WHERE id IN (${ids.map(() => "?").join(",")})`
 *
 * The values still travel separately (`.bind(...ids)`); only the `?` marks are
 * pasted. Likewise a fixed piece of SQL kept in a constant
 * (`const LAST_DAY = "strftime(...)"`). Neither lets a visitor change the
 * statement, so a query built only from such pieces is safe.
 *
 * Proven from the syntax, never guessed. A value counts as fixed when it is:
 *   - a string, number, boolean or null written in the code;
 *   - a template, `+`, `a ? b : c` or `a || b` made only of fixed values;
 *   - `list.map(callback).join(fixed)` where the callback returns fixed text
 *     (its index may be used, `$${i + 1}`, when `list` is a plain array), or
 *     `Array(n).fill(fixed).join()`, or `fixed.repeat(n)`;
 *   - a name declared exactly once in the file, as a `const` holding a fixed
 *     value, in a block that encloses the query.
 * Anything else -- a function call, a property, a name bound twice -- is not.
 * A file with a `with` statement is never trusted: there a name can mean a
 * property of anything.
 */
export function isFixedText(parsed: ParsedFile, node: Node): boolean {
  const { bindings, hasWith } = bindingsOf(parsed);
  if (hasWith) return false;
  return fixed(node, { bindings, use: node }, new Set(), new Set(), 0);
}

interface Binding {
  /** The value of a `const name = value`; undefined for any other kind of binding. */
  constValue?: Node;
  /** The block the binding lives in; a use outside it is some other name. */
  scope?: Node | undefined;
}

interface Context {
  bindings: Map<string, Binding[]>;
  /** The value being judged; every constant it relies on must be in scope there. */
  use: Node;
}

const cache = new WeakMap<ParsedFile, { bindings: Map<string, Binding[]>; hasWith: boolean }>();

const SCOPE = /^(?:Program|BlockStatement|StaticBlock|SwitchStatement|TSModuleBlock|ForStatement|ForInStatement|ForOfStatement)$/;

/** Every place a name is bound in the file: declarations, parameters, imports. */
function bindingsOf(parsed: ParsedFile): { bindings: Map<string, Binding[]>; hasWith: boolean } {
  const known = cache.get(parsed);
  if (known) return known;

  const bindings = new Map<string, Binding[]>();
  let hasWith = false;
  const add = (name: unknown, binding: Binding = {}) => {
    if (typeof name !== "string") return;
    bindings.set(name, [...(bindings.get(name) ?? []), binding]);
  };
  const addAll = (pattern: unknown) => {
    if (typeof pattern !== "object" || pattern === null) return;
    walk(pattern as Node, (n) => {
      if (n.type === "Identifier") add(n.name);
    });
  };

  walk(parsed.program, (node, parents) => {
    switch (node.type) {
      case "VariableDeclarator": {
        const id = node.id as Node;
        const isConst = (parents[0] as { kind?: string } | undefined)?.kind === "const";
        if (id.type === "Identifier" && isConst && node.init) {
          add(id.name, { constValue: node.init as Node, scope: parents.find((p) => SCOPE.test(p.type)) });
        } else addAll(id);
        break;
      }
      case "FunctionDeclaration":
      case "FunctionExpression":
      case "ArrowFunctionExpression":
        if (node.id) addAll(node.id);
        for (const param of (node.params ?? []) as Node[]) addAll(param);
        break;
      case "CatchClause":
        addAll(node.param);
        break;
      case "ClassDeclaration":
      case "ClassExpression":
      case "TSEnumDeclaration":
      case "TSModuleDeclaration":
      case "TSImportEqualsDeclaration":
        addAll(node.id);
        break;
      case "WithStatement":
        hasWith = true;
        break;
      case "ImportSpecifier":
      case "ImportDefaultSpecifier":
      case "ImportNamespaceSpecifier":
        addAll(node.local);
        break;
      case "AssignmentExpression":
        addAll(node.left);
        break;
    }
  });
  const result = { bindings, hasWith };
  cache.set(parsed, result);
  return result;
}

function fixed(
  node: Node | undefined,
  context: Context,
  numbers: Set<string>,
  seen: Set<string>,
  depth: number,
): boolean {
  if (!node || depth > 20) return false;
  const again = (n: unknown, nums = numbers) => fixed(n as Node | undefined, context, nums, seen, depth + 1);

  switch (node.type) {
    case "Literal":
      // A regular expression or bigint also has no plain value; neither counts.
      if (node.regex || node.bigint) return false;
      return node.value === null || ["string", "number", "boolean"].includes(typeof node.value);
    case "TemplateLiteral":
      return ((node.expressions ?? []) as Node[]).every((e) => again(e));
    case "BinaryExpression":
      // `+` joins text; arithmetic on numbers (`i + 1`) stays a number.
      return ["+", "-", "*"].includes(String(node.operator)) && again(node.left) && again(node.right);
    case "ConditionalExpression":
      return again(node.consequent) && again(node.alternate);
    case "LogicalExpression":
      return again(node.left) && again(node.right);
    case "ParenthesizedExpression":
    case "TSAsExpression":
    case "TSNonNullExpression":
    case "TSSatisfiesExpression":
      return again(node.expression);
    case "Identifier": {
      const name = String(node.name);
      if (numbers.has(name)) return true;
      const bound = context.bindings.get(name) ?? [];
      const only = bound.length === 1 ? bound[0]! : undefined;
      if (!only?.constValue || !only.scope || !contains(only.scope, context.use) || seen.has(name)) return false;
      seen.add(name);
      // A callback's index name means nothing inside the constant's own value.
      const result = again(only.constValue, new Set());
      seen.delete(name);
      return result;
    }
    case "CallExpression":
      return fixedCall(node, again);
    default:
      return false;
  }
}

function fixedCall(node: Node, again: (n: unknown, numbers?: Set<string>) => boolean): boolean {
  const callee = node.callee as Node;
  if (callee?.type !== "MemberExpression" || callee.computed) return false;
  const method = dottedName(callee.property);
  const target = callee.object as Node;
  const args = (node.arguments ?? []) as Node[];

  // `"?".repeat(n)`: the count only decides how many.
  if (method === "repeat") return again(target);
  if (method !== "join" || args.length > 1 || (args[0] && !again(args[0]))) return false;

  // `[fixed, fixed].join(...)`
  if (target.type === "ArrayExpression") return ((target.elements ?? []) as Node[]).every((e) => again(e));
  if (target.type !== "CallExpression") return false;

  const inner = target.callee as Node;
  if (inner?.type !== "MemberExpression" || inner.computed) return false;
  const innerArgs = (target.arguments ?? []) as Node[];

  // `Array(n).fill(fixed).join(...)`
  if (dottedName(inner.property) === "fill") return innerArgs.length === 1 && again(innerArgs[0]);
  if (dottedName(inner.property) !== "map" || innerArgs.length !== 1) return false;

  // `list.map(callback).join(...)`: the callback must return fixed text. For
  // a plain array its second parameter is the index, a number, so `$${i + 1}`
  // is still fixed. Wrappers such as lodash's `_(object).map` pass a key
  // there instead, which a visitor may have chosen, so a call that is not
  // known to give an array gets no index.
  const callback = innerArgs[0]!;
  if (callback.type !== "ArrowFunctionExpression" && callback.type !== "FunctionExpression") return false;
  const params = (callback.params ?? []) as Node[];
  const index = params[1]?.type === "Identifier" && givesArray(inner.object as Node)
    ? new Set([String(params[1].name)])
    : new Set<string>();
  const body = callback.body as Node;
  if (body.type !== "BlockStatement") return again(body, index);
  const statements = (body.body ?? []) as Node[];
  return statements.length === 1 && statements[0]!.type === "ReturnStatement" && again(statements[0]!.argument, index);
}

/** A name, a property, or a call known to give a plain array. */
function givesArray(node: Node): boolean {
  if (node.type === "Identifier" || (node.type === "MemberExpression" && !node.computed)) return true;
  if (node.type !== "CallExpression") return false;
  const callee = node.callee as Node;
  if (/^(?:Object\.(?:keys|values|entries)|Array\.(?:from|of))$/.test(dottedName(callee) ?? "")) return true;
  // An array method gives an array only when called on one: `_(q).filter` does not.
  return callee.type === "MemberExpression" && !callee.computed &&
    /^(?:filter|slice|map|concat|flat|flatMap|toSorted|toReversed)$/.test(dottedName(callee.property) ?? "") &&
    givesArray(callee.object as Node);
}
