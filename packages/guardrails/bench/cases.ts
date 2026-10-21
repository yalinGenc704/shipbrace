import type { SinkKind } from "../src/analysis/inventory.ts";

/** A dangerous operation, or "one user can reach another's record". */
export type ClaimKind = SinkKind | "ownership";
import type { SourceFile } from "../src/types.ts";

/**
 * The benchmark: small applications whose right answers are known in advance.
 *
 * Each case is a few files written the way a generated Hono app is written,
 * with every dangerous operation marked by a comment such as `// [A]` on the
 * line where it happens. The answer key says, for each marker, whether that
 * operation can really be reached by a visitor's unchecked input.
 *
 * The decoys matter as much as the real problems. A tool that flags everything
 * scores perfectly on the real ones and is useless; the safe cases are what
 * measure "no warnings on correct code".
 *
 * The code lives in string literals on purpose: reviewing this repository must
 * not report the benchmark's deliberately broken samples as its own problems,
 * and the parser does not read code inside strings.
 *
 * Rule for adding a case: the answer key states what is *true*, not what the
 * tool currently reports. A case the tool gets wrong is the point of having it.
 */

export interface KeyEntry {
  /** Matches the `// [marker]` comment on the dangerous line. */
  marker: string;
  /** The claim a perfect suggester would make about this line. */
  door?: string;
  parameter: string;
  sink: ClaimKind;
  /** True when a visitor can really steer this operation. */
  real: boolean;
  /** Why, in plain language. Shown when the tool gets it wrong. */
  why: string;
}

export interface BenchCase {
  id: string;
  /** What this case tests, in one plain sentence. */
  tests: string;
  files: SourceFile[];
  key: KeyEntry[];
  /**
   * Claims a sloppy suggester might make that are simply wrong: a route or an
   * operation that is not there. A perfect suggester makes none, but the
   * scripted run sends these too, to show the checker throws them out.
   */
  wrongClaims?: Array<{ door?: string; parameter: string; sink: ClaimKind }>;
}

const file = (path: string, lines: string[]): SourceFile => ({ path, content: lines.join("\n") });

const HEAD = ['import { Hono } from "hono";', "const app = new Hono();", ""];

/** An app where everything under /api requires signing in. */
const SIGNED_IN = [...HEAD, 'app.use("/api/*", requireUser);', ""];

export const CASES: BenchCase[] = [
  // --- database ------------------------------------------------------------
  {
    id: "sql-route-param",
    tests: "A value from the address is pasted straight into a database query.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/api/reports/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  const rows = await db.query(`SELECT * FROM reports WHERE id = ${id}`); // [A]",
        "  return c.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/reports/:id",
        parameter: "id",
        sink: "sql",
        real: true,
        why: "The id from the address becomes part of the query text.",
      },
    ],
    wrongClaims: [{ door: "/api/reports/:id", parameter: "id", sink: "shell" }],
  },
  {
    id: "sql-parameterised",
    tests: "The same query written the safe way, with the value sent separately.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/api/reports/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  const rows = await sql`SELECT * FROM reports WHERE id = ${id}`; // [A]",
        "  return c.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/reports/:id",
        parameter: "id",
        sink: "sql",
        real: false,
        why: "A tagged sql template sends the id as data, never as query text.",
      },
    ],
  },
  {
    id: "sql-number",
    tests: "The value is turned into a number before it reaches the query.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/api/reports/:id", async (c) => {',
        '  const raw = c.req.param("id");',
        "  const id = Number(raw);",
        "  const rows = await db.query(`SELECT * FROM reports WHERE id = ${id}`); // [A]",
        "  return c.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/reports/:id",
        parameter: "id",
        sink: "sql",
        real: false,
        why: "A number cannot carry query text.",
      },
    ],
  },
  {
    id: "sql-destructured-body",
    tests: "A field pulled out of a submitted form is pasted into a query.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/api/login", async (c) => {',
        "  const { email } = await c.req.json();",
        "  const user = await db.query(`SELECT * FROM users WHERE email = '${email}'`); // [A]",
        "  return c.json(user);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/login",
        parameter: "email",
        sink: "sql",
        real: true,
        why: "The submitted email becomes part of the query text.",
      },
    ],
  },
  {
    id: "sql-schema-enum",
    tests: "The form is checked against a fixed list of allowed values first.",
    files: [
      file("server/src/index.ts", [
        'import { z } from "zod";',
        ...HEAD,
        'const Filter = z.object({ status: z.enum(["open", "closed"]) });',
        "",
        'app.post("/api/tickets/search", async (c) => {',
        "  const body = await c.req.json();",
        "  const filter = Filter.parse(body);",
        "  const rows = await db.query(`SELECT * FROM tickets WHERE status = '${filter.status}'`); // [A]",
        "  return c.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/tickets/search",
        parameter: "body",
        sink: "sql",
        real: false,
        why: "Only the words 'open' or 'closed' can get past the check.",
      },
    ],
  },
  {
    id: "sql-schema-any-string",
    tests: "The form is 'validated', but the check accepts any text at all.",
    files: [
      file("server/src/index.ts", [
        'import { z } from "zod";',
        ...HEAD,
        "const Search = z.object({ name: z.string() });",
        "",
        'app.post("/api/customers/search", async (c) => {',
        "  const body = await c.req.json();",
        "  const input = Search.parse(body);",
        "  const rows = await db.query(`SELECT * FROM customers WHERE name = '${input.name}'`); // [A]",
        "  return c.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/customers/search",
        parameter: "body",
        sink: "sql",
        real: true,
        why: "Checking that something is text does not stop that text containing query commands.",
      },
    ],
  },
  {
    id: "sql-schema-uuid",
    tests: "The form is checked to be an ID in a fixed format before the query.",
    files: [
      file("server/src/index.ts", [
        'import { z } from "zod";',
        ...HEAD,
        "const Lookup = z.object({ id: z.string().uuid() });",
        "",
        'app.post("/api/orders/lookup", async (c) => {',
        "  const body = await c.req.json();",
        "  const input = Lookup.parse(body);",
        "  const rows = await db.query(`SELECT * FROM orders WHERE id = '${input.id}'`); // [A]",
        "  return c.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/orders/lookup",
        parameter: "body",
        sink: "sql",
        real: false,
        why: "Only letters, digits and dashes in a fixed pattern get through.",
      },
    ],
  },
  {
    id: "sql-schema-mixed",
    tests: "A form with a free-text note and a number; only the number reaches the query.",
    files: [
      file("server/src/index.ts", [
        'import { z } from "zod";',
        ...HEAD,
        "const Update = z.object({ note: z.string(), qty: z.number() });",
        "",
        'app.post("/api/cart/update", async (c) => {',
        "  const body = await c.req.json();",
        "  const input = Update.parse(body);",
        "  await db.query(`UPDATE cart SET qty = ${input.qty} WHERE id = 1`); // [A]",
        "  return c.json({ ok: true });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/cart/update",
        parameter: "body",
        sink: "sql",
        real: false,
        why: "A checked number cannot carry query text.",
      },
    ],
  },
  {
    id: "sql-unrelated-param",
    tests: "A route reads a value but never uses it in the query.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/api/stats/:region", async (c) => {',
        '  const region = c.req.param("region");',
        '  console.log("stats requested", region);',
        '  const table = "daily_stats";',
        "  const rows = await db.query(`SELECT * FROM ${table} LIMIT 10`); // [A]",
        "  return c.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/stats/:region",
        parameter: "region",
        sink: "sql",
        real: false,
        why: "The query only uses a fixed table name written by the developer.",
      },
    ],
  },
  {
    id: "sql-two-routes-same-name",
    tests: "Two routes use the same variable name; only one of them checks it.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/api/orders/:id", async (c) => {',
        '  const raw = c.req.param("id");',
        "  const id = Number(raw);",
        "  return c.json(await db.query(`SELECT * FROM orders WHERE id = ${id}`)); // [A]",
        "});",
        "",
        'app.get("/api/invoices/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  return c.json(await db.query(`SELECT * FROM invoices WHERE id = ${id}`)); // [B]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/orders/:id",
        parameter: "id",
        sink: "sql",
        real: false,
        why: "This route turns the id into a number first.",
      },
      {
        marker: "B",
        door: "/api/invoices/:id",
        parameter: "id",
        sink: "sql",
        real: true,
        why: "This route pastes the id into the query unchanged.",
      },
    ],
  },

  // --- following a value into other code -------------------------------------
  {
    id: "helper-same-file",
    tests: "The route hands the value to a helper function that builds the query.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        "function findProject(slug) {",
        "  return db.query(`SELECT * FROM projects WHERE slug = '${slug}'`); // [A]",
        "}",
        "",
        'app.get("/api/projects/:slug", async (c) => {',
        '  const slug = c.req.param("slug");',
        "  return c.json(await findProject(slug));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/projects/:slug",
        parameter: "slug",
        sink: "sql",
        real: true,
        why: "The helper pastes whatever it is given into the query.",
      },
    ],
  },
  {
    id: "helper-other-file",
    tests: "The helper that builds the query lives in a different file.",
    files: [
      file("server/src/db.ts", [
        "export function findByOwner(owner) {",
        "  return pool.unsafe(`SELECT * FROM notes WHERE owner = '${owner}'`); // [A]",
        "}",
      ]),
      file("server/src/index.ts", [
        'import { findByOwner } from "./db.ts";',
        ...HEAD,
        'app.get("/api/notes", async (c) => {',
        '  const owner = c.req.query("owner");',
        "  return c.json(await findByOwner(owner));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/notes",
        parameter: "owner",
        sink: "sql",
        real: true,
        why: "The helper in db.ts pastes the owner into the query.",
      },
    ],
  },
  {
    id: "helper-two-hops",
    tests: "The value passes through two layers of code before reaching the query.",
    files: [
      file("server/src/repo.ts", [
        "export function selectInvoice(ref) {",
        "  return pool.unsafe(`SELECT * FROM invoices WHERE ref = '${ref}'`); // [A]",
        "}",
      ]),
      file("server/src/service.ts", [
        'import { selectInvoice } from "./repo.ts";',
        "export function loadInvoice(reference) {",
        "  return selectInvoice(reference);",
        "}",
      ]),
      file("server/src/index.ts", [
        'import { loadInvoice } from "./service.ts";',
        ...HEAD,
        'app.get("/api/invoices/:ref", async (c) => {',
        '  const ref = c.req.param("ref");',
        "  return c.json(await loadInvoice(ref));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/invoices/:ref",
        parameter: "ref",
        sink: "sql",
        real: true,
        why: "The reference travels unchanged through the service into the query.",
      },
    ],
  },
  {
    id: "helper-two-hops-checked",
    tests: "Two layers deep again, but the middle layer turns the value into a number.",
    files: [
      file("server/src/repo.ts", [
        "export function selectOrder(orderId) {",
        "  return pool.unsafe(`SELECT * FROM orders WHERE id = ${orderId}`); // [A]",
        "}",
      ]),
      file("server/src/service.ts", [
        'import { selectOrder } from "./repo.ts";',
        "export function loadOrder(raw) {",
        "  const orderId = Number(raw);",
        "  return selectOrder(orderId);",
        "}",
      ]),
      file("server/src/index.ts", [
        'import { loadOrder } from "./service.ts";',
        ...HEAD,
        'app.get("/api/orders/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  return c.json(await loadOrder(id));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/orders/:id",
        parameter: "id",
        sink: "sql",
        real: false,
        why: "The service converts the id to a number before the query sees it.",
      },
    ],
  },

  {
    id: "helper-three-hops",
    tests: "The value passes through three functions in three files, picking up a change on the way.",
    files: [
      file("server/src/repo.ts", [
        "export function runQuery(text) {",
        "  return pool.unsafe(`SELECT * FROM docs WHERE title = '${text}'`); // [A]",
        "}",
      ]),
      file("server/src/search.ts", [
        'import { runQuery } from "./repo.ts";',
        "export function searchTitles(term) {",
        "  const trimmed = term.trim();",
        "  return runQuery(trimmed);",
        "}",
      ]),
      file("server/src/service.ts", [
        'import { searchTitles } from "./search.ts";',
        "export function handleSearch(q) {",
        "  return searchTitles(q);",
        "}",
      ]),
      file("server/src/index.ts", [
        'import { handleSearch } from "./service.ts";',
        ...HEAD,
        'app.get("/api/search", async (c) => {',
        '  const q = c.req.query("q");',
        "  return c.json(await handleSearch(q));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/search",
        parameter: "q",
        sink: "sql",
        real: true,
        why: "Trimming spaces does not make text safe; it still reaches the query.",
      },
    ],
  },
  {
    id: "helper-shared-by-safe-and-unsafe",
    tests: "One helper is used by two routes; only one of them checks its input first.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        "function lookup(key) {",
        "  return db.query(`SELECT * FROM items WHERE id = ${key}`); // [A]",
        "}",
        "",
        'app.get("/api/safe/:id", async (c) => {',
        '  const raw = c.req.param("id");',
        "  const id = Number(raw);",
        "  return c.json(await lookup(id));",
        "});",
        "",
        'app.get("/api/unsafe/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  return c.json(await lookup(id));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/unsafe/:id",
        parameter: "id",
        sink: "sql",
        real: true,
        why: "The unsafe route passes its id to the helper unchecked.",
      },
    ],
    // The safe route's claim names the same line, so it cannot be a separate
    // key entry; sent as a claim, it must not be what confirms the line.
    wrongClaims: [{ door: "/api/safe/:id", parameter: "id", sink: "sql" }],
  },

  // --- system commands -------------------------------------------------------
  {
    id: "shell-github-clone",
    tests: "A GitHub address typed by a visitor is pasted into a system command.",
    files: [
      file("server/src/index.ts", [
        'import { execSync } from "node:child_process";',
        ...HEAD,
        'app.post("/api/import", async (c) => {',
        "  const { repoUrl } = await c.req.json();",
        "  execSync(`git clone ${repoUrl} /tmp/work`); // [A]",
        "  return c.json({ ok: true });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/import",
        parameter: "repoUrl",
        sink: "shell",
        real: true,
        why: "The address is read by a shell, which treats parts of it as commands.",
      },
    ],
    wrongClaims: [{ door: "/api/export", parameter: "repoUrl", sink: "shell" }],
  },
  {
    id: "shell-args-array",
    tests: "The same import, with the address handed to git as a separate argument.",
    files: [
      file("server/src/index.ts", [
        'import { execFileSync } from "node:child_process";',
        ...HEAD,
        'app.post("/api/import", async (c) => {',
        "  const { repoUrl } = await c.req.json();",
        '  execFileSync("git", ["clone", "--", repoUrl, "/tmp/work"]); // [A]',
        "  return c.json({ ok: true });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/import",
        parameter: "repoUrl",
        sink: "shell",
        real: false,
        why: "No shell reads the address; git receives it as one plain value.",
      },
    ],
  },

  // --- files ---------------------------------------------------------------
  {
    id: "file-download",
    tests: "A file name from the address picks which file on the server is sent back.",
    files: [
      file("server/src/index.ts", [
        'import { readFile } from "node:fs/promises";',
        'import { join } from "node:path";',
        ...HEAD,
        'app.get("/api/files", async (c) => {',
        '  const name = c.req.query("name");',
        '  const data = await readFile(join("/srv/uploads", name)); // [A]',
        "  return c.body(data);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/files",
        parameter: "name",
        sink: "filesystem",
        real: true,
        why: "A name like ../../etc/passwd climbs out of the uploads folder.",
      },
    ],
  },
  {
    id: "file-basename",
    tests: "The same download, with the folder part stripped from the name first.",
    files: [
      file("server/src/index.ts", [
        'import { readFile } from "node:fs/promises";',
        'import { basename, join } from "node:path";',
        ...HEAD,
        'app.get("/api/files", async (c) => {',
        '  const name = c.req.query("name");',
        "  const safeName = basename(name);",
        '  const data = await readFile(join("/srv/uploads", safeName)); // [A]',
        "  return c.body(data);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/files",
        parameter: "name",
        sink: "filesystem",
        real: false,
        why: "Only the bare file name survives, so it cannot leave the folder.",
      },
    ],
  },
  {
    id: "file-from-header",
    tests: "A browser language setting picks which file is read.",
    files: [
      file("server/src/index.ts", [
        'import { readFileSync } from "node:fs";',
        ...HEAD,
        'app.get("/api/strings", (c) => {',
        '  const lang = c.req.header("accept-language");',
        "  const text = readFileSync(`./locales/${lang}.json`, \"utf8\"); // [A]",
        "  return c.text(text);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/strings",
        parameter: "accept-language",
        sink: "filesystem",
        real: true,
        why: "A visitor controls that setting and can point it at any file.",
      },
    ],
  },

  // --- pages ---------------------------------------------------------------
  {
    id: "html-search-echo",
    tests: "A search term is written straight into the page shown back to the visitor.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/search", (c) => {',
        '  const q = c.req.query("q");',
        "  return c.html(`<h1>Results for ${q}</h1>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/search",
        parameter: "q",
        sink: "html",
        real: true,
        why: "A search term containing script tags runs in the visitor's browser.",
      },
    ],
  },
  {
    id: "html-react-raw",
    tests: "A comment from the database is shown with React's raw-HTML escape hatch.",
    files: [
      file("app/src/Comment.tsx", [
        "export function Comment({ body }) {",
        "  return <div dangerouslySetInnerHTML={{ __html: body }} />; // [A]",
        "}",
      ]),
    ],
    key: [
      {
        marker: "A",
        parameter: "body",
        sink: "html",
        real: true,
        why: "Whoever wrote the comment can put a script in it for every reader.",
      },
    ],
  },

  {
    id: "html-hono-escaped",
    tests: "The same search page, built with Hono's html helper, which escapes values.",
    files: [
      file("server/src/index.ts", [
        'import { html } from "hono/html";',
        ...HEAD,
        'app.get("/search", (c) => {',
        '  const q = c.req.query("q");',
        "  return c.html(html`<h1>Results for ${q}</h1>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/search",
        parameter: "q",
        sink: "html",
        real: false,
        why: "The html helper turns script tags into harmless text.",
      },
    ],
  },

  // --- stored attacks: saved by one visitor, shown to the next ----------------
  {
    id: "stored-comment-raw",
    tests: "A comment form saves what visitors type; the comments page pastes it into the page as-is.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/comments", async (c) => {',
        "  const body = await c.req.json();",
        '  await c.env.DB.prepare("INSERT INTO comments (author, text) VALUES (?, ?)").bind(body.author, body.text).run();',
        "  return c.json({ ok: true });",
        "});",
        "",
        'app.get("/comments", async (c) => {',
        '  const { results } = await c.env.DB.prepare("SELECT author, text FROM comments").all();',
        '  const items = results.map((r) => `<li>${r.author}: ${r.text}</li>`).join("");',
        "  return c.html(`<ul>${items}</ul>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/comments",
        parameter: "text",
        sink: "html",
        real: true,
        why: "Anyone can post a comment containing a script, and it runs for every later reader.",
      },
    ],
  },

  {
    id: "stored-mongoose-raw",
    tests: "An Express app saves a guestbook entry whole and sends the entries back as raw markup.",
    files: [
      file("server/routes.js", [
        'const express = require("express");',
        "const app = express();",
        'app.post("/guestbook", async (req, res) => {',
        "  await Entry.create(req.body);",
        "  res.redirect('/guestbook');",
        "});",
        'app.get("/guestbook", async (req, res) => {',
        "  const entries = await Entry.find();",
        "  res.send(`<div>${entries.map((e) => e.message).join('<br>')}</div>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/guestbook",
        parameter: "message",
        sink: "html",
        real: true,
        why: "A guestbook message can carry a script that runs for everyone who opens the page.",
      },
    ],
  },

  {
    id: "stored-comment-escaped",
    tests: "The same comments page, built with Hono's html helper, which escapes what visitors saved.",
    files: [
      file("server/src/index.ts", [
        'import { html } from "hono/html";',
        ...HEAD,
        'app.post("/comments", async (c) => {',
        "  const body = await c.req.json();",
        '  await c.env.DB.prepare("INSERT INTO comments (author, text) VALUES (?, ?)").bind(body.author, body.text).run();',
        "  return c.json({ ok: true });",
        "});",
        "",
        'app.get("/comments", async (c) => {',
        '  const { results } = await c.env.DB.prepare("SELECT author, text FROM comments").all();',
        "  return c.html(html`<ul>${results.map((r) => html`<li>${r.text}</li>`)}</ul>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/comments",
        parameter: "text",
        sink: "html",
        real: false,
        why: "The html helper turns anything saved by a visitor into harmless text.",
      },
    ],
  },

  {
    id: "stored-app-written-raw",
    tests: "A page shows a visit log the app writes itself; no visitor's text is ever saved in it.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/visit", async (c) => {',
        "  const at = new Date().toISOString();",
        '  await c.env.DB.prepare("INSERT INTO visits (at, source) VALUES (?, ?)").bind(at, "web").run();',
        "  return c.json({ ok: true });",
        "});",
        "",
        'app.get("/visits", async (c) => {',
        '  const { results } = await c.env.DB.prepare("SELECT at, source FROM visits").all();',
        '  const rows = results.map((r) => `<li>${r.at} from ${r.source}</li>`).join("");',
        "  return c.html(`<ul>${rows}</ul>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/visits",
        parameter: "source",
        sink: "html",
        real: false,
        why: "Only the app writes to this table, with a fixed word and the time, so a visitor cannot put anything in it.",
      },
    ],
  },

  {
    id: "stored-number-checked",
    tests: "A rating is saved only after being turned into a number, then shown on a page.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/ratings", async (c) => {',
        "  const body = await c.req.json();",
        "  const stars = Number(body.stars);",
        '  await c.env.DB.prepare("INSERT INTO ratings (stars) VALUES (?)").bind(stars).run();',
        "  return c.json({ ok: true });",
        "});",
        "",
        'app.get("/ratings", async (c) => {',
        '  const { results } = await c.env.DB.prepare("SELECT stars FROM ratings").all();',
        '  const rows = results.map((r) => `<li>${r.stars} stars</li>`).join("");',
        "  return c.html(`<ul>${rows}</ul>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/ratings",
        parameter: "stars",
        sink: "html",
        real: false,
        why: "Only numbers are ever saved, and a number cannot carry a script.",
      },
    ],
  },

  {
    id: "stored-row-picked-only",
    tests: "A visitor's id only picks which post gets a view counted; post titles are shown raw but only the app writes them.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/posts/:id/view", async (c) => {',
        '  await c.env.DB.prepare("UPDATE posts SET views = views + 1 WHERE id = ?").bind(c.req.param("id")).run();',
        "  return c.json({ ok: true });",
        "});",
        "",
        'app.get("/posts", async (c) => {',
        '  const { results } = await c.env.DB.prepare("SELECT title FROM posts").all();',
        '  const rows = results.map((r) => `<li>${r.title}</li>`).join("");',
        "  return c.html(`<ul>${rows}</ul>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/posts",
        parameter: "title",
        sink: "html",
        real: false,
        why: "The visitor's value only chooses which row's counter goes up; it is never saved as text anyone sees.",
      },
    ],
  },

  {
    id: "stored-prisma-where-only",
    tests: "Prisma: a visitor's id is used only in `where` to mark a post read; post titles come from the app.",
    files: [
      file("server/routes.js", [
        'app.post("/posts/:id/read", async (req, res) => {',
        "  await prisma.post.update({ where: { id: req.params.id }, data: { read: true } });",
        "  res.end();",
        "});",
        'app.get("/posts", async (req, res) => {',
        "  const posts = await prisma.post.findMany();",
        "  res.send(`<ul>${posts.map((p) => p.title).join('')}</ul>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/posts",
        parameter: "title",
        sink: "html",
        real: false,
        why: "Only a fixed true/false is saved; the visitor's id just picks the post.",
      },
    ],
  },

  {
    id: "stored-other-column",
    tests: "A visitor's value is saved in one column, but the page shows a different column only the app writes.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/likes", async (c) => {',
        "  const body = await c.req.json();",
        '  await c.env.DB.prepare("INSERT INTO likes (post_id, label) VALUES (?, \'liked\')").bind(body.postId).run();',
        "  return c.json({ ok: true });",
        "});",
        "",
        'app.get("/likes", async (c) => {',
        '  const { results } = await c.env.DB.prepare("SELECT label FROM likes").all();',
        '  const rows = results.map((r) => `<li>${r.label}</li>`).join("");',
        "  return c.html(`<ul>${rows}</ul>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/likes",
        parameter: "label",
        sink: "html",
        real: false,
        why: "The page shows only the label column, which always holds the fixed word the app wrote.",
      },
    ],
  },

  // --- a check for the wrong kind of danger ---------------------------------
  {
    id: "escape-html-before-shell",
    tests: "A host name is HTML-escaped, then pasted into a shell command; HTML escaping leaves `;` alone.",
    files: [
      file("server/src/index.ts", [
        'import { execSync } from "node:child_process";',
        'import { escapeHtml } from "./util";',
        ...HEAD,
        'app.get("/ping", (c) => {',
        '  const host = c.req.query("host");',
        "  const safe = escapeHtml(host);",
        "  return c.text(execSync(`ping -c 1 ${safe}`).toString()); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/ping",
        parameter: "host",
        sink: "shell",
        real: true,
        why: "Escaping for a web page does nothing to `; rm -rf /`, so the visitor can still run any command.",
      },
    ],
  },

  {
    id: "escape-shell-before-shell",
    tests: "The same command, with the host quoted for the shell first.",
    files: [
      file("server/src/index.ts", [
        'import { execSync } from "node:child_process";',
        'import { quote } from "shell-quote";',
        ...HEAD,
        'app.get("/ping", (c) => {',
        '  const host = c.req.query("host");',
        "  const safe = quote([host]);",
        "  return c.text(execSync(`ping -c 1 ${safe}`).toString()); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/ping",
        parameter: "host",
        sink: "shell",
        real: false,
        why: "Quoting for the shell makes the whole value one harmless argument.",
      },
    ],
  },

  {
    id: "escape-html-before-redirect",
    tests: "A next-page address is HTML-escaped and then followed; escaping does not stop a link to another site.",
    files: [
      file("server/src/index.ts", [
        'import { escapeHtml } from "./util";',
        ...HEAD,
        'app.get("/after-login", (c) => {',
        '  const next = c.req.query("next");',
        "  const clean = escapeHtml(next);",
        "  return c.redirect(clean); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/after-login",
        parameter: "next",
        sink: "redirect",
        real: true,
        why: "https://evil.example contains nothing HTML escaping changes, so visitors can still be sent anywhere.",
      },
    ],
  },

  // --- redirects -----------------------------------------------------------
  {
    id: "redirect-open",
    tests: "After signing in, the visitor is sent wherever the address says.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/after-login", (c) => {',
        '  const next = c.req.query("next");',
        "  return c.redirect(next); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/after-login",
        parameter: "next",
        sink: "redirect",
        real: true,
        why: "A link to your site can bounce people to a lookalike site.",
      },
    ],
  },
  {
    id: "redirect-allowlist",
    tests: "The same redirect, but only to a fixed list of your own pages.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'const ALLOWED = ["/dashboard", "/settings"];',
        "",
        'app.get("/after-login", (c) => {',
        '  const next = c.req.query("next");',
        '  if (!ALLOWED.includes(next)) return c.redirect("/dashboard");',
        "  return c.redirect(next); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/after-login",
        parameter: "next",
        sink: "redirect",
        real: false,
        why: "Anything not on the list is sent to the dashboard instead.",
      },
    ],
  },
  {
    id: "redirect-check-that-blocks-nothing",
    tests: "The value is looked at, but the check only logs; it never stops anything.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/after-login", (c) => {',
        '  const next = c.req.query("next");',
        '  if (next.includes("://")) console.warn("external redirect", next);',
        "  return c.redirect(next); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/after-login",
        parameter: "next",
        sink: "redirect",
        real: true,
        why: "The check writes a warning and then redirects anyway.",
      },
    ],
  },

  {
    id: "redirect-allowlist-stored",
    tests: "The allowlist answer is saved first, then used to refuse.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'const ALLOWED = ["/dashboard", "/settings"];',
        "",
        'app.get("/after-login", (c) => {',
        '  const next = c.req.query("next");',
        "  const allowed = ALLOWED.includes(next);",
        '  if (!allowed) return c.redirect("/dashboard");',
        "  return c.redirect(next); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/after-login",
        parameter: "next",
        sink: "redirect",
        real: false,
        why: "Anything not on the list is still refused, one step later.",
      },
    ],
  },

  // --- outbound requests -----------------------------------------------------
  {
    id: "fetch-link-preview",
    tests: "The server fetches any website address a visitor submits.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/api/preview", async (c) => {',
        "  const { url } = await c.req.json();",
        "  const page = await fetch(url); // [A]",
        "  return c.text(await page.text());",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/preview",
        parameter: "url",
        sink: "outbound-request",
        real: true,
        why: "A visitor can make your server open internal addresses only it can reach.",
      },
    ],
  },

  // --- one user reaching another's records -------------------------------------
  //
  // Only a suggester can raise these: whether a record is private is a
  // judgement about what the app is for. The queries are all written the safe
  // way, so nothing here is an injection problem -- a safe query can still
  // fetch the wrong person's row.
  {
    id: "ownership-invoice",
    tests: "Signed-in users fetch an invoice by its number, and nothing checks it is theirs.",
    files: [
      file("server/src/index.ts", [
        ...SIGNED_IN,
        'app.get("/api/invoices/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  const rows = await sql`SELECT * FROM invoices WHERE id = ${id}`; // [A]",
        "  return c.json(rows[0]);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/invoices/:id",
        parameter: "id",
        sink: "ownership",
        real: true,
        why: "Changing the number in the address shows someone else's invoice.",
      },
    ],
  },
  {
    id: "ownership-in-query",
    tests: "The same lookup, limited to invoices owned by whoever is signed in.",
    files: [
      file("server/src/index.ts", [
        ...SIGNED_IN,
        'app.get("/api/invoices/:id", async (c) => {',
        '  const id = c.req.param("id");',
        '  const userId = c.get("userId");',
        "  const rows = await sql`SELECT * FROM invoices WHERE id = ${id} AND owner_id = ${userId}`; // [A]",
        "  return c.json(rows[0]);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/invoices/:id",
        parameter: "id",
        sink: "ownership",
        real: false,
        why: "Someone else's invoice simply is not found.",
      },
    ],
  },
  {
    id: "ownership-checked-after",
    tests: "The invoice is fetched first, then refused if it belongs to someone else.",
    files: [
      file("server/src/index.ts", [
        ...SIGNED_IN,
        'app.get("/api/invoices/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  const rows = await sql`SELECT * FROM invoices WHERE id = ${id}`; // [A]",
        '  if (rows[0]?.owner_id !== c.get("userId")) return c.json({ error: "Not found" }, 404);',
        "  return c.json(rows[0]);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/invoices/:id",
        parameter: "id",
        sink: "ownership",
        real: false,
        why: "The route refuses before showing anything that is not yours.",
      },
    ],
  },
  {
    id: "ownership-through-helper",
    tests: "The lookup happens in a helper in another file, and nothing checks the owner.",
    files: [
      file("server/src/messages.ts", [
        "export function loadMessage(messageId) {",
        "  return sql`SELECT * FROM messages WHERE id = ${messageId}`; // [A]",
        "}",
      ]),
      file("server/src/index.ts", [
        'import { loadMessage } from "./messages.ts";',
        ...SIGNED_IN,
        'app.get("/api/messages/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  return c.json(await loadMessage(id));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/messages/:id",
        parameter: "id",
        sink: "ownership",
        real: true,
        why: "Anyone signed in can read any message by its number.",
      },
    ],
  },
  {
    id: "ownership-orm-shown-only",
    tests: "A user record is loaded through Sequelize by an id from the form; the signed-in user is only printed, never compared.",
    files: [
      file("server/routes/users.js", [
        'const router = require("express").Router();',
        'router.post("/useredit", requireLogin, (req, res) => {',
        "  db.User.find({ where: { id: req.body.id } }).then((user) => { // [A]",
        "    user.email = req.body.email;",
        "    user.save();",
        '    res.render("useredit", { userId: req.user.id });',
        "  });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/useredit",
        parameter: "id",
        sink: "ownership",
        real: true,
        why: "Any signed-in user can change anyone's email by sending a different id.",
      },
    ],
  },
  {
    id: "ownership-orm-checked",
    tests: "The same edit, but the lookup also requires the record to belong to whoever is signed in.",
    files: [
      file("server/routes/users.js", [
        'const router = require("express").Router();',
        'router.post("/useredit", requireLogin, (req, res) => {',
        "  db.User.find({ where: { id: req.body.id, ownerId: req.user.id } }).then((user) => { // [A]",
        "    user.email = req.body.email;",
        "    user.save();",
        "  });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/useredit",
        parameter: "id",
        sink: "ownership",
        real: false,
        why: "Someone else's record is simply not found.",
      },
    ],
  },
  {
    id: "ownership-public-page",
    tests: "A public product page looked up by id; there is no owner and no sign-in.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/products/:id", async (c) => {',
        '  const id = c.req.param("id");',
        "  const rows = await sql`SELECT * FROM products WHERE id = ${id}`; // [A]",
        "  return c.json(rows[0]);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/products/:id",
        parameter: "id",
        sink: "ownership",
        real: false,
        why: "Products are meant for everyone to see.",
      },
    ],
  },

  // --- Express, the most common older framework ----------------------------------
  {
    id: "express-sql-concat",
    tests: "An Express route builds a query by joining text with +, reading the form inline.",
    files: [
      file("server/routes/users.js", [
        'const router = require("express").Router();',
        'router.post("/usersearch", requireLogin, (req, res) => {',
        `  const query = "SELECT name FROM Users WHERE login='" + req.body.login + "'"; // [A]`,
        "  db.sequelize.query(query).then((rows) => res.json(rows));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/usersearch",
        parameter: "login",
        sink: "sql",
        real: true,
        why: "A login containing a quote mark rewrites the query.",
      },
    ],
  },
  {
    id: "express-sql-concat-number",
    tests: "The same query, but the value is turned into a number first.",
    files: [
      file("server/routes/users.js", [
        'const router = require("express").Router();',
        'router.get("/users/:id", requireLogin, (req, res) => {',
        "  const id = parseInt(req.params.id, 10);",
        '  const query = "SELECT name FROM Users WHERE id=" + id; // [A]',
        "  db.sequelize.query(query).then((rows) => res.json(rows));",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/users/:id",
        parameter: "id",
        sink: "sql",
        real: false,
        why: "A number cannot carry query text.",
      },
    ],
  },
  {
    id: "express-unserialize-upload",
    tests: "An uploaded file is turned back into objects with node-serialize.",
    files: [
      file("server/routes/products.js", [
        'const serialize = require("node-serialize");',
        'const router = require("express").Router();',
        'router.post("/products/import", requireLogin, (req, res) => {',
        '  const products = serialize.unserialize(req.files.products.data.toString("utf8")); // [A]',
        "  res.json(products);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/products/import",
        parameter: "files",
        sink: "dynamic-code",
        real: true,
        why: "The file can contain a function that runs on your server as it is read.",
      },
    ],
  },

  {
    id: "template-ejs-raw",
    tests: "A search term is passed to an EJS page that prints it raw.",
    files: [
      file("server/routes/search.js", [
        'const router = require("express").Router();',
        'router.get("/search", requireLogin, (req, res) => {',
        '  res.render("search", { term: req.query.q }); // [A]',
        "});",
      ]),
      file("views/search.ejs", ["<h1>Results for <%- term %></h1>"]),
    ],
    key: [
      {
        marker: "A",
        door: "/search",
        parameter: "q",
        sink: "html",
        real: true,
        why: "A search term containing script tags runs in the visitor's browser.",
      },
    ],
  },
  {
    id: "template-ejs-escaped",
    tests: "The same page, printing the term the safe way.",
    files: [
      file("server/routes/search.js", [
        'const router = require("express").Router();',
        'router.get("/search", requireLogin, (req, res) => {',
        '  res.render("search", { term: req.query.q }); // [A]',
        "});",
      ]),
      file("views/search.ejs", ["<h1>Results for <%= term %></h1>"]),
    ],
    key: [
      {
        marker: "A",
        door: "/search",
        parameter: "q",
        sink: "html",
        real: false,
        why: "EJS turns script tags into harmless text when printing with <%=.",
      },
    ],
  },
  {
    id: "template-raw-other-value",
    tests: "The page prints one value raw, but the visitor's term goes to a value it escapes.",
    files: [
      file("server/routes/search.js", [
        'const router = require("express").Router();',
        'router.get("/search", requireLogin, (req, res) => {',
        '  res.render("search", { banner: BANNER_HTML, term: req.query.q }); // [A]',
        "});",
      ]),
      file("views/search.ejs", ["<%- banner %><h1>Results for <%= term %></h1>"]),
    ],
    key: [
      {
        marker: "A",
        door: "/search",
        parameter: "q",
        sink: "html",
        real: false,
        why: "Only the developer's own banner is printed raw.",
      },
    ],
  },
  {
    id: "template-handlebars-raw-reassigned",
    tests: "A Handlebars page prints a value raw that was built from the search term in a plain reassignment.",
    files: [
      file("server/routes/search.js", [
        'const router = require("express").Router();',
        'router.get("/results", requireLogin, (req, res) => {',
        "  let summary;",
        "  summary = `You searched for ${req.query.q}`;",
        '  res.render("results", { summary }); // [A]',
        "});",
      ]),
      file("views/results.hbs", ["<div>{{{ summary }}}</div>"]),
    ],
    key: [
      {
        marker: "A",
        door: "/results",
        parameter: "q",
        sink: "html",
        real: true,
        why: "The search term ends up inside the raw summary.",
      },
    ],
  },

  // --- MongoDB-style queries ----------------------------------------------------------
  {
    id: "mongo-login-bypass",
    tests: "A login looks the user up with the form's values passed straight into a MongoDB filter.",
    files: [
      file("server/routes/login.js", [
        'const router = require("express").Router();',
        'router.post("/login", async (req, res) => {',
        "  const user = await User.findOne({ email: req.body.email, password: req.body.password }); // [A]",
        "  res.json({ ok: Boolean(user) });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/login",
        parameter: "password",
        sink: "nosql",
        real: true,
        why: 'Sending {"$ne": null} as the password matches any user.',
      },
    ],
  },
  {
    id: "mongo-login-as-text",
    tests: "The same login, with each value turned into plain text first.",
    files: [
      file("server/routes/login.js", [
        'const router = require("express").Router();',
        'router.post("/login", async (req, res) => {',
        "  const user = await User.findOne({ email: String(req.body.email), password: String(req.body.password) }); // [A]",
        "  res.json({ ok: Boolean(user) });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/login",
        parameter: "password",
        sink: "nosql",
        real: false,
        why: "A string cannot carry query operators.",
      },
    ],
  },
  {
    id: "mongo-where-built",
    tests: "A MongoDB $where condition is assembled from a value in the address.",
    files: [
      file("server/routes/allocations.js", [
        'const router = require("express").Router();',
        'router.get("/allocations", requireLogin, async (req, res) => {',
        "  const threshold = req.query.threshold;",
        "  const rows = await allocationsCol.find({ $where: `this.stocks > ${threshold}` }); // [A]",
        "  res.json(rows);",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/allocations",
        parameter: "threshold",
        sink: "nosql",
        real: true,
        why: "$where runs JavaScript inside the database, and the visitor writes part of it.",
      },
    ],
  },
  {
    id: "sequelize-where-safe",
    tests: "A Sequelize lookup with the same field names; Sequelize sends values as data.",
    files: [
      file("server/routes/login.js", [
        'const router = require("express").Router();',
        'router.post("/login", async (req, res) => {',
        "  const user = await User.findOne({ where: { email: req.body.email } }); // [A]",
        "  res.json({ ok: Boolean(user) });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/login",
        parameter: "email",
        sink: "nosql",
        real: false,
        why: "Sequelize's where filter does not treat values as operators.",
      },
    ],
  },

  // --- uploaded files ----------------------------------------------------------
  {
    id: "upload-filename",
    tests: "An uploaded file is saved under the name the uploader gave it.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/api/upload", async (c) => {',
        "  const body = await c.req.parseBody();",
        '  const upload = body["file"];',
        "  await Bun.write(`./uploads/${upload.name}`, upload); // [A]",
        "  return c.json({ ok: true });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/upload",
        parameter: "body",
        sink: "filesystem",
        real: true,
        why: "A file named ../../server/src/index.ts overwrites your own code.",
      },
    ],
  },
  {
    id: "upload-filename-basename",
    tests: "The same upload, with the folder part stripped from the name first.",
    files: [
      file("server/src/index.ts", [
        'import { basename, join } from "node:path";',
        ...HEAD,
        'app.post("/api/upload", async (c) => {',
        "  const body = await c.req.parseBody();",
        '  const upload = body["file"];',
        "  const safeName = basename(upload.name);",
        '  await Bun.write(join("./uploads", safeName), upload); // [A]',
        "  return c.json({ ok: true });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/upload",
        parameter: "body",
        sink: "filesystem",
        real: false,
        why: "Only the bare file name survives, so it stays in the uploads folder.",
      },
    ],
  },
  {
    id: "upload-own-name",
    tests: "The upload is saved under a name the server makes up; only its contents come from the visitor.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/api/upload", async (c) => {',
        "  const body = await c.req.parseBody();",
        '  const upload = body["file"];',
        "  await Bun.write(`./uploads/${crypto.randomUUID()}.bin`, upload); // [A]",
        "  return c.json({ ok: true });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/upload",
        parameter: "body",
        sink: "filesystem",
        real: false,
        why: "What is written is the visitor's, but where it is written is not.",
      },
    ],
  },
  {
    id: "upload-express-multer",
    tests: "An Express app saves an upload under its original name.",
    files: [
      file("server/src/index.ts", [
        'import fs from "node:fs";',
        'import express from "express";',
        'import multer from "multer";',
        "const app = express();",
        "const upload = multer({ storage: multer.memoryStorage() });",
        "",
        'app.post("/upload", upload.single("doc"), (req, res) => {',
        "  const name = req.file.originalname;",
        "  fs.writeFileSync(`uploads/${name}`, req.file.buffer); // [A]",
        "  res.json({ ok: true });",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/upload",
        parameter: "name",
        sink: "filesystem",
        real: true,
        why: "The uploader picks the file name, folders and all.",
      },
    ],
  },

  // --- content from someone else's repository --------------------------------------
  {
    id: "repo-readme-shown",
    tests: "A linked GitHub repository's README is shown on a page as-is.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.post("/api/import", async (c) => {',
        "  const { owner, repo } = await c.req.json();",
        "  const { data } = await octokit.rest.repos.getReadme({ owner, repo });",
        '  const text = Buffer.from(data.content, "base64").toString();',
        "  return c.html(`<article>${text}</article>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/import",
        parameter: "data",
        sink: "html",
        real: true,
        why: "Whoever owns that repository can put a script in its README.",
      },
    ],
  },
  {
    id: "repo-readme-escaped",
    tests: "The same README, shown through Hono's escaping html helper.",
    files: [
      file("server/src/index.ts", [
        'import { html } from "hono/html";',
        ...HEAD,
        'app.post("/api/import", async (c) => {',
        "  const { owner, repo } = await c.req.json();",
        "  const { data } = await octokit.rest.repos.getReadme({ owner, repo });",
        '  const text = Buffer.from(data.content, "base64").toString();',
        "  return c.html(html`<article>${text}</article>`); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/import",
        parameter: "data",
        sink: "html",
        real: false,
        why: "Scripts in the README are shown as text, not run.",
      },
    ],
  },

  // --- settings values -----------------------------------------------------------
  {
    id: "ci-pr-title",
    tests: "A build script puts a pull request's title into a system command.",
    files: [
      file("scripts/release-notes.ts", [
        'import { execSync } from "node:child_process";',
        "const title = process.env.PR_TITLE;",
        'execSync(`git tag -a v1.0.0 -m "${title}"`); // [A]',
      ]),
    ],
    key: [
      {
        marker: "A",
        parameter: "title",
        sink: "shell",
        real: true,
        why: "Anyone who opens a pull request chooses its title, and a title can contain commands.",
      },
    ],
  },
  {
    id: "ci-database-url",
    tests: "A backup script puts the database address from settings into a command.",
    files: [
      file("scripts/backup.ts", [
        'import { execSync } from "node:child_process";',
        "const url = process.env.DATABASE_URL;",
        "execSync(`pg_dump ${url} > backup.sql`); // [A]",
      ]),
    ],
    key: [
      {
        marker: "A",
        parameter: "url",
        sink: "shell",
        real: false,
        why: "Only whoever runs the server sets the database address.",
      },
    ],
  },

  // --- running code ----------------------------------------------------------
  {
    id: "eval-calculator",
    tests: "A calculator runs whatever formula the visitor types as code.",
    files: [
      file("server/src/index.ts", [
        ...HEAD,
        'app.get("/api/calc", (c) => {',
        '  const expr = c.req.query("expr");',
        "  return c.json({ result: eval(expr) }); // [A]",
        "});",
      ]),
    ],
    key: [
      {
        marker: "A",
        door: "/api/calc",
        parameter: "expr",
        sink: "dynamic-code",
        real: true,
        why: "Any code typed in runs on your server with full access.",
      },
    ],
  },
];
