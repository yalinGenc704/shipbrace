import type { RepoSnapshot } from "../types.ts";
import { isSource, isTestPath } from "../util.ts";
import { dottedName, isStringLiteral, parseFile, walk, type Node } from "./ast.ts";

/**
 * What fields each table or model has, read from the project's own
 * definitions: Prisma models, SQL `CREATE TABLE`, Mongoose schemas,
 * Sequelize `define`/`init`, and Drizzle tables.
 *
 * Used to judge mass assignment. Saving a visitor's whole form is only a
 * problem when the record has a field the visitor must not choose -- a role,
 * an admin flag, an owner -- so the answer depends on the table. A table
 * whose fields cannot be found is simply absent, and nothing is said about it.
 */

/** Fields a visitor must never set by sending them along with a form. */
export const SENSITIVE_FIELD =
  /^(?:roles?|is_?admin|admin|is_?staff|is_?superuser|superuser|permissions?|scopes?|is_?verified|verified|email_?verified|balance|credits?|plan|tier|owner(?:_?id)?|user_?id|author_?id|account_?id|org(?:anization)?_?id|tenant_?id|is_?approved|approved)$/i;

/** Same normalisation as stored-data names: lower case, trailing "s" removed. */
export const modelName = (raw: string): string => raw.toLowerCase().replace(/s$/, "");

export interface ModelFields {
  /** Every field found, lower case. */
  fields: string[];
  /** The fields a visitor must not set. */
  sensitive: string[];
}

export function modelFields(snapshot: RepoSnapshot): Map<string, ModelFields> {
  const found = new Map<string, Set<string>>();
  const add = (model: string, fields: string[]): void => {
    const set = found.get(modelName(model)) ?? new Set<string>();
    for (const f of fields) if (f) set.add(f);
    found.set(modelName(model), set);
  };

  for (const file of snapshot.files) {
    if (isTestPath(file.path)) continue;
    if (file.path.endsWith(".prisma")) {
      for (const [, model, body] of file.content.matchAll(/^model\s+(\w+)\s*\{([\s\S]*?)^\}/gm)) {
        add(model!, body!.split("\n").map((l) => l.trim().split(/\s+/)[0] ?? "").filter((w) => /^\w+$/.test(w)));
      }
    }
    if (file.path.endsWith(".sql") || isSource(file.path)) {
      for (const [model, fields] of createTables(file.content)) add(model, fields);
    }
    if (isSource(file.path)) {
      for (const [model, fields] of codeModels(file.path, file.content)) add(model, fields);
    }
  }

  const result = new Map<string, ModelFields>();
  for (const [model, set] of found) {
    const fields = [...set].map((f) => f.toLowerCase());
    result.set(model, { fields, sensitive: fields.filter((f) => SENSITIVE_FIELD.test(f)) });
  }
  return result;
}

/** `CREATE TABLE name ( col type, ... )`, with brackets inside types handled. */
function createTables(text: string): Array<[string, string[]]> {
  const tables: Array<[string, string[]]> = [];
  const re = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["`[]?(\w+)["`\]]?\s*\(/gi;
  for (const match of text.matchAll(re)) {
    let depth = 1;
    let i = match.index! + match[0].length;
    const start = i;
    while (i < text.length && depth > 0) {
      if (text[i] === "(") depth++;
      else if (text[i] === ")") depth--;
      i++;
    }
    const columns: string[] = [];
    let part = "";
    let level = 0;
    for (const ch of text.slice(start, i - 1) + ",") {
      if (ch === "(") level++;
      if (ch === ")") level--;
      if (ch === "," && level === 0) {
        const word = part.trim().split(/\s+/)[0]?.replace(/["`[\]]/g, "") ?? "";
        if (word && !/^(?:primary|foreign|unique|constraint|check|index|key)$/i.test(word)) columns.push(word.toLowerCase());
        part = "";
      } else part += ch;
    }
    tables.push([match[1]!, columns]);
  }
  return tables;
}

/** Keys of an object literal. */
function keysOf(node: Node | undefined): string[] {
  if (node?.type !== "ObjectExpression") return [];
  return ((node.properties ?? []) as Node[]).flatMap((prop) => {
    const key = prop.key as Node | undefined;
    const name = key?.type === "Identifier" ? key.name : isStringLiteral(key) ? key.value : undefined;
    return name === undefined ? [] : [String(name).toLowerCase()];
  });
}

/** Mongoose, Sequelize and Drizzle models written in code. */
function codeModels(path: string, content: string): Array<[string, string[]]> {
  if (!/Schema|define|\.init\(|Table\(/.test(content)) return [];
  const parsed = parseFile({ path, content });
  if (!parsed) return [];

  const models: Array<[string, string[]]> = [];
  const schemas = new Map<string, string[]>();
  const later: Array<{ model: string; schema: string }> = [];

  walk(parsed.program, (node, parents) => {
    if (node.type === "NewExpression" && /(?:^|\.)Schema$/.test(dottedName(node.callee) ?? "")) {
      const fields = keysOf(((node.arguments ?? []) as Node[])[0]);
      const holder = parents[0];
      if (holder?.type === "VariableDeclarator" && (holder.id as Node | undefined)?.type === "Identifier") {
        schemas.set(String((holder.id as Node).name), fields);
      }
      // `model("User", new Schema({...}))`
      const call = parents[0];
      if (call?.type === "CallExpression" && /(?:^|\.)model$/.test(dottedName(call.callee) ?? "")) {
        const name = ((call.arguments ?? []) as Node[])[0];
        if (isStringLiteral(name)) models.push([String(name.value), fields]);
      }
    }
    if (node.type !== "CallExpression") return;
    const callee = dottedName(node.callee) ?? "";
    const args = (node.arguments ?? []) as Node[];
    // `mongoose.model("User", userSchema)`
    if (/(?:^|\.)model$/.test(callee) && isStringLiteral(args[0]) && args[1]?.type === "Identifier") {
      later.push({ model: String(args[0].value), schema: String(args[1].name) });
    }
    // Sequelize `sequelize.define("User", {...})`; Drizzle `pgTable("users", {...})`.
    if (/(?:^|\.)(?:define|pgTable|mysqlTable|sqliteTable)$/.test(callee) && isStringLiteral(args[0])) {
      models.push([String(args[0].value), keysOf(args[1])]);
    }
    // Sequelize `User.init({...}, { sequelize })`
    if (/^[A-Z]\w*\.init$/.test(callee)) models.push([callee.split(".")[0]!, keysOf(args[0])]);
  });

  for (const { model, schema } of later) {
    const fields = schemas.get(schema);
    if (fields) models.push([model, fields]);
  }
  return models;
}
