import { codeOnly, dottedName, parseFile, walk, type Node } from "../analysis/ast.ts";
import { isSource, isTestPath } from "../util.ts";
import type { ProjectCheck } from "./checks.ts";
import type { Risk } from "./modules.ts";

/**
 * Project checks that read files rather than follow values: database row
 * rules, the container's user, debug settings, upload limits, and packages.
 *
 * Each says `not-applicable` when the project has nothing it can judge, so an
 * item never passes on a question nobody asked.
 */

function risk(id: string, grade: Risk["grade"], what: string, impact: string, fix: string, path: string, line: number, detail?: string): Risk {
  return { id: `${id}@${path}:${line}`, grade, what, impact, fix, ...(detail ? { fixDetail: detail } : {}), location: { path, line }, confirmedBy: "rule" };
}

// --- Supabase: tables the browser can reach need row rules -------------------

const SUPABASE_PROJECT = /(?:^|\/)supabase\/(?:config\.toml|migrations\/)/;

const CREATES_TABLE = /CREATE\s+(?:UNLOGGED\s+)?TABLE\b/i;

// Comments and function bodies (between $$ quotes) are not statements run
// by the migration, so a `create table` inside one does not count.
const bare = (text: string): string =>
  text.replace(/\$(\w*)\$[\s\S]*?\$\1\$/g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/\/\*[\s\S]*?\*\//g, (m) => m.replace(/[^\n]/g, " "))
    .replace(/--[^\n]*/g, (m) => " ".repeat(m.length));

/**
 * With Supabase the browser talks to the database directly, using a key that
 * is public by design. Any table in the `public` schema without row level
 * security can then be read and changed by anyone holding that key -- every
 * visitor. Judged from the project's SQL migrations; tables made elsewhere
 * (the dashboard) cannot be seen, which the item says.
 */
export const supabaseRowRules: ProjectCheck = {
  id: "supabase:row-level-security",
  itemId: "access-control/database-rules",

  run(snapshot) {
    // Any Supabase package (supabase-js, ssr, auth helpers), in either list, or
    // an import of one in the code. Not in tests, and not in sample code kept
    // as text: a checker's own test that imports Supabase inside a string does
    // not make the checker a Supabase app.
    const usesSupabase = snapshot.files.some((f) => SUPABASE_PROJECT.test(f.path)) ||
      [...snapshot.manifests.values()].some((m) =>
        Object.keys({ ...(m.dependencies as object | undefined), ...(m.devDependencies as object | undefined) })
          .some((name) => name.startsWith("@supabase/"))
      ) ||
      snapshot.files.some((f) =>
        isSource(f.path) && !isTestPath(f.path) && /from\s+["']@supabase\/|require\(\s*["']@supabase\//.test(codeOnly(f))
      );
    if (!usesSupabase) {
      return { status: "not-applicable", reason: "This app doesn't use Supabase, the only database this item is about.", absent: true };
    }
    // When Supabase's own folder creates tables, only that SQL sets up
    // Supabase tables. Other SQL in the same repository (a Cloudflare D1 or
    // SQLite database, say) is a database the browser cannot reach. A folder
    // holding only seed data does not count: the tables are made elsewhere.
    const allSql = snapshot.files.filter((f) => f.path.endsWith(".sql") && !isTestPath(f.path));
    const inSupabase = allSql.filter((f) => /(?:^|\/)supabase\//.test(f.path));
    const sql = inSupabase.some((f) => CREATES_TABLE.test(bare(f.content))) ? inSupabase : allSql;
    if (sql.length === 0) {
      return {
        status: "not-applicable",
        reason: "Your Supabase table setup files weren't found, so this could not be checked. Open your Supabase dashboard and confirm every table shows Row Level Security as enabled.",
      };
    }

    const all = sql.map((f) => bare(f.content)).join("\n");
    // Only an `enable` on the public table itself counts: `private.notes`
    // having row rules does nothing for `public.notes`.
    const secured = securedTables(all);
    const risks: Risk[] = [];
    for (const { file, table, line } of openTables(sql, secured)) {
      risks.push(risk(
        "check/supabase-no-rls",
        "high",
        `Anyone visiting your site can read, change or delete everything in the \`${table}\` table. It has no lock on who may see each row (Row Level Security).`,
        "Supabase lets visitors' browsers talk to your database directly. Without that lock, every row in this table is open to all of them.",
        "Turn on Row Level Security for this table, and add rules that let each person reach only their own rows.",
        file.path,
        line,
        `Add \`alter table public.${table} enable row level security;\` in a new migration, then create policies limiting each user to their own rows (for example \`using (auth.uid() = user_id)\`).`,
      ));
    }

    const buckets = [...all.matchAll(/insert\s+into\s+storage\.buckets[^;]*?values\s*\(\s*'([^']+)'[^;]*?\btrue\b/gi)].map((m) => m[1]!);
    const notice = buckets.length > 0
      ? `Public file storage: ${buckets.join(", ")}. Anyone with a file's address can download it -- fine for pictures meant to be seen, not for private documents.`
      : undefined;
    if (risks.length > 0) return { status: "risks", risks, ...(notice ? { notice } : {}) };

    // SQL outside Supabase's folder was left out. It may be another database
    // (a Cloudflare D1 one) or more Supabase tables made with another tool;
    // the files cannot say which, so tables there without a lock go back to
    // the user rather than passing.
    const leftOutSql = allSql.filter((f) => !sql.includes(f));
    const securedThere = securedTables(leftOutSql.map((f) => bare(f.content)).join("\n"));
    const leftOut = openTables(leftOutSql, new Set([...secured, ...securedThere]));
    if (leftOut.length > 0) {
      const files = [...new Set(leftOut.map((t) => t.file.path))];
      return {
        status: "not-applicable",
        reason: `Your Supabase tables all have Row Level Security, but ${files.join(", ")} also create${files.length === 1 ? "s" : ""} tables without it (${[...new Set(leftOut.map((t) => t.table))].join(", ")}). If those are in your Supabase database too, turn Row Level Security on for them; if they belong to a different database, nothing is needed.`,
        ...(notice ? { notice } : {}),
      };
    }
    return { status: "pass", ...(notice ? { notice } : {}) };
  },
};

/** Public tables given row level security in this SQL. */
const securedTables = (sql: string): Set<string> =>
  new Set(
    [...sql.matchAll(/ALTER\s+TABLE\s+(?:ONLY\s+)?(?:IF\s+EXISTS\s+)?((?:"?\w+"?\.)?)"?(\w+)"?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi)]
      .filter((m) => ["", "public"].includes(m[1]!.replace(/["."]/g, "").toLowerCase()))
      .map((m) => m[2]!.toLowerCase()),
  );

/** Public tables a set of SQL files creates without row level security. */
function openTables(files: Array<{ path: string; content: string }>, secured: Set<string>) {
  const found: Array<{ file: { path: string; content: string }; table: string; line: number }> = [];
  for (const file of files) {
    const text = bare(file.content);
    for (const match of text.matchAll(/CREATE\s+(?:UNLOGGED\s+)?TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?((?:"?\w+"?\.)?)"?(\w+)"?/gi)) {
      const schema = match[1]!.replace(/["."]/g, "").toLowerCase();
      const table = match[2]!.toLowerCase();
      if ((schema && schema !== "public") || secured.has(table)) continue;
      found.push({ file, table, line: text.slice(0, match.index).split("\n").length });
    }
  }
  return found;
}

// --- Containers: the app should not run as root ------------------------------

const DOCKERFILE = /(?:^|\/)Dockerfile(?:\.[\w-]+)?$|\.dockerfile$/i;
/** Files for local work, not for running the app for real. */
const DEV_FILE = /(?:^|[./-])(?:dev|development|local|test|override)(?:[./-]|$)/i;
const deployed = (path: string): boolean =>
  !DEV_FILE.test(path.split("/").pop() ?? "") && !/(?:^|\/)\.devcontainer\//.test(path) && !isTestPath(path);

/** The stages of a Dockerfile: each FROM line, its image, its alias, and its lines. */
function stagesOf(content: string): Array<{ image: string; alias?: string; start: number; lines: string[] }> {
  const lines = content.split(/\r?\n/);
  const stages: Array<{ image: string; alias?: string; start: number; lines: string[] }> = [];
  lines.forEach((line, i) => {
    if (/^\s*FROM\s/i.test(line)) {
      const words = line.trim().split(/\s+/).slice(1).filter((w) => !w.startsWith("--"));
      const as = words.findIndex((w) => /^as$/i.test(w));
      stages.push({ image: words[0] ?? "", ...(as >= 0 && words[as + 1] ? { alias: words[as + 1]!.toLowerCase() } : {}), start: i, lines: [] });
    }
    stages.at(-1)?.lines.push(line);
  });
  return stages;
}

/**
 * The last stage of a Dockerfile is what runs. Without a `USER` line (or
 * with `USER root`) the app runs as root inside the container, so anyone who
 * gets it to run a command can change anything in it, and escaping the
 * container is far easier. Images that run as a non-root user by default
 * (`...:nonroot`, `chainguard/...`) are fine.
 */
export const containerUser: ProjectCheck = {
  id: "docker:non-root-user",
  itemId: "config/container-user",

  run(snapshot) {
    const files = snapshot.files.filter((f) => DOCKERFILE.test(f.path) && deployed(f.path));
    if (files.length === 0) return { status: "not-applicable", reason: "This app isn't packaged with a Dockerfile, so there is no container to check.", absent: true };

    const risks: Risk[] = [];
    for (const file of files) {
      const stages = stagesOf(file.content);
      // The user a stage runs as: its own last USER line, or the one of the
      // earlier stage it is built FROM (`FROM base`).
      const userOf = (index: number, depth = 0): { user?: string; line?: number; image: string } => {
        const stage = stages[index]!;
        const own = stage.lines.map((l, i) => [l, i] as const).filter(([l]) => /^\s*USER\s/i.test(l)).at(-1);
        if (own) return { user: own[0].trim().split(/\s+/)[1]!, line: stage.start + own[1] + 1, image: stage.image };
        const parent = stages.findIndex((s, i) => i < index && s.alias === stage.image.toLowerCase());
        return parent >= 0 && depth < 8 ? { ...userOf(parent, depth + 1), image: stage.image } : { image: stage.image };
      };
      if (stages.length === 0) continue;
      const { user, line } = userOf(stages.length - 1);
      const image = stages.at(-1)!.image;
      const nonRootImage = /nonroot|^cgr\.dev\/|chainguard/i.test(image);
      if (user ? !/^(?:root|0)(?::|$)/.test(user) : nonRootImage) continue;
      risks.push(risk(
        "check/container-root",
        "medium",
        `Your app's setup file (${file.path}) runs it with full administrator rights on its machine (as "root").`,
        "If someone finds a way to run a command through your app, they can change anything around it. Breaking out to the computer underneath is also much easier.",
        "Run the app as an ordinary user with limited rights.",
        file.path,
        line ?? stages.at(-1)!.start + 1,
        `In ${file.path}, add \`USER node\` (on Node images) or create an unprivileged user, after copying files and installing packages in the final stage${user ? ", replacing USER root" : ""}.`,
      ));
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- Debug settings in what gets deployed -------------------------------------

const COMPOSE = /(?:^|\/)(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml$/i;

/**
 * Development mode in a Dockerfile or compose file ships with the app:
 * Express then shows visitors full error details, and many libraries turn on
 * extra logging. Only what is written in those files is judged; settings in
 * a hosting dashboard cannot be seen, which the item says.
 */
export const debugOff: ProjectCheck = {
  id: "deploy:debug-off",
  itemId: "config/debug-off",

  run(snapshot) {
    const files = snapshot.files.filter((f) => (DOCKERFILE.test(f.path) || COMPOSE.test(f.path)) && deployed(f.path));
    if (files.length === 0) {
      return { status: "not-applicable", reason: "We couldn't see how your live site is started. If you use a hosting service (Vercel, Netlify, Render and similar), check its settings show production mode." };
    }
    const DEBUG = /\bNODE_ENV\s*[=:]\s*["']?development\b|\bDEBUG\s*[=:]\s*["']?(?:true|1|\*)["']?\s*$/im;
    const risks: Risk[] = [];
    for (const f of files) {
      // A Dockerfile's final stage is what runs; build stages and ARG defaults
      // do not reach it. Comments say nothing.
      const lines = DOCKERFILE.test(f.path) ? stagesOf(f.content).at(-1)?.lines ?? [] : f.content.split(/\r?\n/);
      const offset = DOCKERFILE.test(f.path) ? stagesOf(f.content).at(-1)?.start ?? 0 : 0;
      const at = lines.findIndex((l) => !/^\s*(?:#|ARG\s)/i.test(l) && DEBUG.test(l));
      if (at < 0) continue;
      risks.push(risk(
        "check/debug-on",
        "medium",
        `${f.path} starts your live app in test (development or debug) mode.`,
        "Test mode shows visitors full error details -- file names and code -- and records extra activity that can include private data.",
        "Switch the live app to production mode, and keep test settings in a separate file for your own computer.",
        f.path,
        offset + at + 1,
        `In ${f.path}, set NODE_ENV=production and remove DEBUG settings; move development settings to a compose.dev.yaml or .env.local that is not used to deploy.`,
      ));
    }
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- Upload size limits --------------------------------------------------------

/**
 * multer accepts files of any size unless `limits` is set. One visitor can
 * then fill the disk or memory with a single upload. Only multer is judged:
 * formidable and busboy-based helpers set limits by default.
 */
export const uploadLimits: ProjectCheck = {
  id: "uploads:size-limit",
  itemId: "design/upload-limits",

  run(snapshot) {
    const risks: Risk[] = [];
    let found = false;
    for (const file of snapshot.files) {
      if (!isSource(file.path) || isTestPath(file.path) || !/multer/.test(file.content)) continue;
      const parsed = parseFile(file);
      if (!parsed) continue;
      walk(parsed.program, (node) => {
        if (node.type !== "CallExpression" || !/(?:^|\.)multer$/.test(dottedName(node.callee) ?? "")) return;
        found = true;
        const options = ((node.arguments ?? []) as Node[])[0];
        const hasLimits = options?.type === "ObjectExpression" &&
          ((options.properties ?? []) as Node[]).some((p) => (p.key as Node | undefined)?.name === "limits");
        // Options built elsewhere (a variable, a spread) might carry limits; say nothing.
        const spreads = options?.type === "ObjectExpression" &&
          ((options.properties ?? []) as Node[]).some((p) => p.type === "SpreadElement");
        if (hasLimits || spreads || (options && options.type !== "ObjectExpression")) return;
        const line = file.content.slice(0, node.start).split("\n").length;
        risks.push(risk(
          "check/upload-no-limit",
          "medium",
          `An upload feature (in ${file.path}) accepts files of any size.`,
          "One visitor can upload a file big enough to fill the server's storage or memory, and stop the site for everyone.",
          "Set a size limit on uploads, as small as your feature allows.",
          file.path,
          line,
          `In ${file.path} line ${line}, pass a limit: \`multer({ dest, limits: { fileSize: 5 * 1024 * 1024 } })\` (5 MB).`,
        ));
      });
    }
    if (!found) return { status: "not-applicable", reason: "We didn't find an upload feature we know how to check (only multer is checked). If visitors can upload files, confirm there's a size limit." };
    return risks.length > 0 ? { status: "risks", risks } : { status: "pass" };
  },
};

// --- Packages: misspelled names, install scripts, unused ones ------------------

/** Widely used packages, and well-known packages whose names sit one letter from another's. */
const POPULAR = new Set(
  ("react react-dom preact redux express lodash axios next vue typescript webpack moment chalk commander debug " +
    "dotenv request mongoose mongodb mysql mysql2 sequelize prisma jsonwebtoken bcrypt bcryptjs cors helmet morgan " +
    "body-parser multer socket.io nodemon eslint tslint prettier mocha vitest rollup esbuild yargs inquirer " +
    "rimraf fs-extra cross-env concurrently node-fetch superagent crypto-js validator dayjs date-fns classnames " +
    "styled-components tailwindcss postcss autoprefixer graphql passport express-session cookie-parser colors color " +
    "colour semver minimist form-data js-yaml xml2js marked handlebars mustache chart.js electron svelte typeorm " +
    "knex sqlite3 better-sqlite3 firebase aws-sdk stripe openai puppeteer cheerio jquery underscore bluebird " +
    "nodemailer ioredis redis sharp fastify hono zod uuid koa colord sqlite reactn openapi prism axiom").split(" "),
);

/** One insertion, deletion, substitution or swap of neighbours apart. */
function oneEditApart(a: string, b: string): boolean {
  if (a === b || Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diff = [...a].map((c, i) => (c === b[i] ? -1 : i)).filter((i) => i >= 0);
    if (diff.length === 1) return true;
    return diff.length === 2 && diff[1] === diff[0]! + 1 && a[diff[0]!] === b[diff[1]!] && a[diff[1]!] === b[diff[0]!];
  }
  const [short, long] = a.length < b.length ? [a, b] : [b, a];
  for (let i = 0; i < long.length; i++) if (long.slice(0, i) + long.slice(i + 1) === short) return true;
  return false;
}

/**
 * Packages that are one letter away from a popular one are the classic way
 * malware gets installed: `expres`, `lodahs`. A name can be a legitimate
 * lookalike, so these hand the item back for a person to confirm rather than
 * calling them risks. Install scripts and unused packages are listed in the
 * item's notice: worth knowing, not problems in themselves.
 */
export const suspiciousPackages: ProjectCheck = {
  id: "manifest:package-names",
  itemId: "components/suspicious-packages",

  run(snapshot) {
    if (snapshot.manifests.size === 0) return { status: "not-applicable", reason: "No package list (package.json) was found, so there are no package names to check.", absent: true };
    const local = new Set([...snapshot.manifests.values()].map((m) => m.name).filter(Boolean));
    const deps = new Map<string, "dependency" | "dev">();
    for (const manifest of snapshot.manifests.values()) {
      for (const name of Object.keys({ ...(manifest.dependencies as object | undefined) })) deps.set(name, "dependency");
      for (const name of Object.keys({ ...(manifest.devDependencies as object | undefined) })) if (!deps.has(name)) deps.set(name, "dev");
    }

    const lookalikes = [...deps.keys()]
      .filter((name) => !local.has(name) && !POPULAR.has(name) && name.length >= 5 && !name.startsWith("@"))
      .flatMap((name) => {
        const like = [...POPULAR].find((p) => p.length >= 5 && oneEditApart(name, p));
        return like ? [`${name} (looks like ${like})`] : [];
      });

    const notes: string[] = [];
    const lock = snapshot.files.find((f) => /(?:^|\/)package-lock\.json$/.test(f.path));
    if (lock) {
      try {
        const packages = (JSON.parse(lock.content) as { packages?: Record<string, { hasInstallScript?: boolean }> }).packages ?? {};
        const scripted = Object.entries(packages)
          .filter(([path, info]) => path && info.hasInstallScript)
          .map(([path]) => path.split("node_modules/").pop()!);
        if (scripted.length > 0) {
          notes.push(`Packages that run their own code when installed: ${[...new Set(scripted)].slice(0, 12).join(", ")}${scripted.length > 12 ? ", …" : ""}. Usually build tools; worth knowing.`);
        }
      } catch {
        // An unreadable lockfile is reported by the lockfile check, not here.
      }
    }
    const code = snapshot.files.filter((f) => !f.path.endsWith("package.json") && !/lock/.test(f.path)).map((f) => f.content).join("\n");
    const scripts = [...snapshot.manifests.values()].map((m) => JSON.stringify(m.scripts ?? {})).join(" ");
    const unused = [...deps.entries()]
      .filter(([name, kind]) => kind === "dependency" && !local.has(name) && !name.startsWith("@types/"))
      .filter(([name]) => !code.includes(`"${name}`) && !code.includes(`'${name}`) && !code.includes(`\`${name}`) && !scripts.includes(name))
      .map(([name]) => name);
    if (unused.length > 0) {
      notes.push(`Packages nothing seems to use: ${unused.slice(0, 12).join(", ")}${unused.length > 12 ? ", …" : ""}. Removing them means less code that could go wrong.`);
    }
    const notice = notes.length > 0 ? notes.join(" ") : undefined;

    if (lookalikes.length > 0) {
      return {
        status: "not-applicable",
        reason: `These packages are named one letter away from popular ones: ${lookalikes.join(", ")}. Misspelled names are a common way harmful code gets installed, so confirm each is the package you meant.`,
        ...(notice ? { notice } : {}),
      };
    }
    return { status: "pass", ...(notice ? { notice } : {}) };
  },
};

export const fileChecks: ProjectCheck[] = [supabaseRowRules, containerUser, debugOff, uploadLimits, suspiciousPackages];
